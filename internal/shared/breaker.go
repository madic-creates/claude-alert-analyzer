package shared

import (
	"errors"
	"sync"
	"time"
)

// ErrCircuitOpen is returned by CircuitBreaker.Acquire when the breaker is
// open or when a probe is already in flight in half-open state.
var ErrCircuitOpen = errors.New("circuit breaker open")

type breakerState int

const (
	breakerClosed breakerState = iota
	breakerOpen
	breakerHalfOpen
)

// CircuitBreaker gates logical analysis attempts. THRESHOLD <= 0 → nil
// receiver (disabled). All methods are nil-safe.
type CircuitBreaker struct {
	threshold        int
	openDuration     time.Duration
	maxProbeDuration time.Duration
	now              func() time.Time

	mu               sync.Mutex
	state            breakerState
	consecFailures   int
	openedAt         time.Time
	probeStartedAt   time.Time
	halfOpenInFlight bool
}

// Permit is a call-token returned by Acquire(). Done(err) must be called
// exactly once per non-nil Permit (idempotent: extra calls are no-ops).
type Permit struct {
	breaker *CircuitBreaker
	isProbe bool
	used    bool
}

// IsProbe returns true for the single half-open probe permit.
func (p *Permit) IsProbe() bool {
	if p == nil {
		return false
	}
	return p.isProbe
}

// Done records the outcome of the call covered by this permit.
// Idempotent: only the first call has an effect. Nil-safe on the receiver.
func (p *Permit) Done(err error) {
	if p == nil {
		return
	}
	if p.breaker == nil {
		p.used = true
		return
	}
	p.breaker.recordResult(p, err)
}

// NewCircuitBreaker constructs a breaker with the given thresholds and clock.
// threshold <= 0 returns nil ("disabled"). Defaults applied for zero
// durations: openDuration=60s, maxProbeDuration=60s.
func NewCircuitBreaker(threshold int, openDuration, maxProbeDuration time.Duration, now func() time.Time) *CircuitBreaker {
	if threshold <= 0 {
		return nil
	}
	if openDuration <= 0 {
		openDuration = 60 * time.Second
	}
	if maxProbeDuration <= 0 {
		maxProbeDuration = 60 * time.Second
	}
	if now == nil {
		now = time.Now
	}
	return &CircuitBreaker{
		threshold:        threshold,
		openDuration:     openDuration,
		maxProbeDuration: maxProbeDuration,
		now:              now,
		state:            breakerClosed,
	}
}

// Acquire checks the breaker state and returns a Permit or ErrCircuitOpen.
// nil receiver returns a no-op permit (used=true) so disabled breakers
// require no special handling at the call site.
func (b *CircuitBreaker) Acquire() (*Permit, error) {
	if b == nil {
		return &Permit{used: true}, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()

	// Probe-watchdog: in-flight probe past the deadline counts as failed.
	if b.halfOpenInFlight && now.Sub(b.probeStartedAt) >= b.maxProbeDuration {
		b.halfOpenInFlight = false
		b.state = breakerOpen
		b.openedAt = now
	}

	switch b.state {
	case breakerClosed:
		return &Permit{breaker: b, isProbe: false}, nil
	case breakerOpen:
		if now.Sub(b.openedAt) < b.openDuration {
			return nil, ErrCircuitOpen
		}
		b.state = breakerHalfOpen
		fallthrough
	case breakerHalfOpen:
		if b.halfOpenInFlight {
			return nil, ErrCircuitOpen
		}
		b.halfOpenInFlight = true
		b.probeStartedAt = now
		return &Permit{breaker: b, isProbe: true}, nil
	default:
		return nil, ErrCircuitOpen
	}
}

func (b *CircuitBreaker) recordResult(p *Permit, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if p.used {
		return
	}
	p.used = true

	if p.isProbe {
		// If halfOpenInFlight is already false the probe-watchdog (in Acquire)
		// has already fired for this probe — it cleared the flag, transitioned
		// the breaker to open, and treated the probe as failed. A late Done()
		// call here must NOT override that decision: otherwise a slow probe
		// that eventually returns nil could re-close a breaker the watchdog
		// just re-opened, silently defeating the safety mechanism. A late
		// Done(err) would similarly extend the open period by overwriting
		// openedAt. Drop the late result on the floor instead.
		if !b.halfOpenInFlight {
			return
		}
		b.halfOpenInFlight = false
		if err == nil {
			b.state = breakerClosed
			b.consecFailures = 0
		} else {
			b.state = breakerOpen
			b.openedAt = b.now()
		}
		return
	}

	if err == nil {
		b.consecFailures = 0
		return
	}
	b.consecFailures++
	if b.consecFailures >= b.threshold {
		b.state = breakerOpen
		b.openedAt = b.now()
	}
}

// State returns the current state as an integer (0=closed, 1=open, 2=halfOpen).
// Used by metrics-recording code; not part of the public Permit API.
//
// The probe-watchdog transition (halfOpen → open on probe timeout) is applied
// lazily inside Acquire(). State() mirrors that check so that the
// claude_circuit_breaker_state gauge stays accurate during quiet periods
// when no Acquire() call has fired the transition yet.
func (b *CircuitBreaker) State() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	// Mirror the probe-watchdog logic from Acquire(): if the in-flight probe
	// has exceeded maxProbeDuration, the effective state is open even though
	// b.state still holds breakerHalfOpen (the lazy transition fires on the
	// next Acquire() call). Returning 1 here keeps the metric accurate.
	if b.state == breakerHalfOpen && b.halfOpenInFlight &&
		b.now().Sub(b.probeStartedAt) >= b.maxProbeDuration {
		return 1
	}
	switch b.state {
	case breakerOpen:
		return 1
	case breakerHalfOpen:
		return 2
	}
	return 0
}
