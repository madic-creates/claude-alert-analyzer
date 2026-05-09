package shared

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCircuitBreaker_NilWhenDisabled(t *testing.T) {
	if b := NewCircuitBreaker(0, time.Second, time.Second, time.Now); b != nil {
		t.Fatalf("threshold=0 → nil, got %v", b)
	}
	if b := NewCircuitBreaker(-1, time.Second, time.Second, time.Now); b != nil {
		t.Fatalf("threshold=-1 → nil, got %v", b)
	}
}

func TestCircuitBreaker_NilReceiverAcquireNoOpPermit(t *testing.T) {
	var b *CircuitBreaker
	p, err := b.Acquire()
	if err != nil || p == nil {
		t.Fatalf("nil-Acquire: p=%v err=%v", p, err)
	}
	if p.IsProbe() {
		t.Fatal("nil-Acquire: IsProbe should be false")
	}
	p.Done(errors.New("any err"))
}

func TestCircuitBreaker_ClosedToOpenOnThreshold(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	b := NewCircuitBreaker(2, time.Minute, time.Minute, clk.Now)

	p, err := b.Acquire()
	if err != nil || p.IsProbe() {
		t.Fatalf("call 1 acquire: err=%v probe=%v", err, p.IsProbe())
	}
	p.Done(errors.New("fail"))

	p, err = b.Acquire()
	if err != nil {
		t.Fatalf("call 2 acquire: err=%v", err)
	}
	p.Done(errors.New("fail"))

	if _, err := b.Acquire(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("call 3: err=%v, want ErrCircuitOpen", err)
	}
}

func TestCircuitBreaker_OpenToHalfOpenAfterDuration(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	b := NewCircuitBreaker(1, 30*time.Second, time.Minute, clk.Now)

	p, _ := b.Acquire()
	p.Done(errors.New("fail"))

	clk.advance(29 * time.Second)
	if _, err := b.Acquire(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("during open: err=%v, want ErrCircuitOpen", err)
	}

	clk.advance(2 * time.Second)
	p, err := b.Acquire()
	if err != nil {
		t.Fatalf("post-open Acquire: err=%v", err)
	}
	if !p.IsProbe() {
		t.Fatal("post-open Acquire: IsProbe should be true")
	}
}

func TestCircuitBreaker_HalfOpenProbeSuccessClosesBreaker(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	b := NewCircuitBreaker(1, 10*time.Second, time.Minute, clk.Now)

	p, _ := b.Acquire()
	p.Done(errors.New("fail"))

	clk.advance(11 * time.Second)
	probe, _ := b.Acquire()
	if !probe.IsProbe() {
		t.Fatal("expected probe permit")
	}
	probe.Done(nil)

	p, err := b.Acquire()
	if err != nil || p.IsProbe() {
		t.Fatalf("post-success: err=%v probe=%v", err, p.IsProbe())
	}
}

func TestCircuitBreaker_HalfOpenProbeFailureReopens(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	b := NewCircuitBreaker(1, 10*time.Second, time.Minute, clk.Now)

	p, _ := b.Acquire()
	p.Done(errors.New("fail"))
	clk.advance(11 * time.Second)
	probe, _ := b.Acquire()
	probe.Done(errors.New("probe failed"))

	if _, err := b.Acquire(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("post-probe-fail: err=%v, want ErrCircuitOpen", err)
	}
}

func TestCircuitBreaker_HalfOpenSinglePermit(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	b := NewCircuitBreaker(1, 10*time.Second, time.Minute, clk.Now)

	p, _ := b.Acquire()
	p.Done(errors.New("fail"))
	clk.advance(11 * time.Second)

	probe, err := b.Acquire()
	if err != nil || !probe.IsProbe() {
		t.Fatalf("first half-open Acquire: err=%v probe=%v", err, probe.IsProbe())
	}
	if _, err := b.Acquire(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("second half-open Acquire: err=%v, want ErrCircuitOpen", err)
	}
}

func TestCircuitBreaker_DoneIsIdempotent(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	b := NewCircuitBreaker(2, time.Minute, time.Minute, clk.Now)

	p, _ := b.Acquire()
	p.Done(errors.New("fail"))
	p.Done(errors.New("fail again"))
	p.Done(errors.New("and again"))

	p, _ = b.Acquire()
	p.Done(errors.New("fail"))
	if _, err := b.Acquire(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("expected open after 2 distinct failures; got %v", err)
	}
}

func TestCircuitBreaker_ProbeWatchdogReleasesStuckProbe(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	b := NewCircuitBreaker(1, 10*time.Second, 5*time.Second, clk.Now)

	p, _ := b.Acquire()
	p.Done(errors.New("fail"))
	clk.advance(11 * time.Second)
	probe, _ := b.Acquire()
	if !probe.IsProbe() {
		t.Fatal("expected probe")
	}
	// "Stuck" — never call probe.Done()

	clk.advance(4 * time.Second)
	if _, err := b.Acquire(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("during probe: err=%v, want ErrCircuitOpen", err)
	}

	clk.advance(2 * time.Second)
	if _, err := b.Acquire(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("post-watchdog: err=%v, want ErrCircuitOpen (state=open)", err)
	}
}

func TestCircuitBreaker_ConcurrentHalfOpenAcquireGivesOnlyOneProbe(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	b := NewCircuitBreaker(1, 10*time.Second, time.Minute, clk.Now)
	p, _ := b.Acquire()
	p.Done(errors.New("fail"))
	clk.advance(11 * time.Second)

	const N = 100
	var probes int64
	var rejected int64
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			perm, err := b.Acquire()
			if err != nil {
				atomic.AddInt64(&rejected, 1)
				return
			}
			if perm.IsProbe() {
				atomic.AddInt64(&probes, 1)
			}
		}()
	}
	wg.Wait()
	if probes != 1 {
		t.Fatalf("probes=%d, want 1", probes)
	}
	if rejected != N-1 {
		t.Fatalf("rejected=%d, want %d", rejected, N-1)
	}
}

// TestCircuitBreaker_State verifies that State() returns the correct integer
// for each breaker state and is nil-safe. State() is called by both pipeline
// implementations to update the claude_circuit_breaker_state Prometheus gauge;
// its three return values (0=closed, 1=open, 2=half-open) must be stable.
func TestCircuitBreaker_State(t *testing.T) {
	t.Run("nil_returns_closed", func(t *testing.T) {
		var b *CircuitBreaker
		if got := b.State(); got != 0 {
			t.Fatalf("nil State() = %d, want 0 (closed)", got)
		}
	})

	t.Run("fresh_breaker_is_closed", func(t *testing.T) {
		clk := &fakeClock{t: time.Unix(0, 0)}
		b := NewCircuitBreaker(2, time.Minute, time.Minute, clk.Now)
		if got := b.State(); got != 0 {
			t.Fatalf("closed State() = %d, want 0", got)
		}
	})

	t.Run("open_after_threshold_failures", func(t *testing.T) {
		clk := &fakeClock{t: time.Unix(0, 0)}
		b := NewCircuitBreaker(2, time.Minute, time.Minute, clk.Now)

		p, _ := b.Acquire()
		p.Done(errors.New("fail"))
		p, _ = b.Acquire()
		p.Done(errors.New("fail"))

		if got := b.State(); got != 1 {
			t.Fatalf("open State() = %d, want 1", got)
		}
	})

	t.Run("half_open_after_open_duration", func(t *testing.T) {
		clk := &fakeClock{t: time.Unix(0, 0)}
		b := NewCircuitBreaker(1, 10*time.Second, time.Minute, clk.Now)

		p, _ := b.Acquire()
		p.Done(errors.New("fail"))

		clk.advance(11 * time.Second)
		// Acquire() transitions open→half-open and issues the probe permit.
		probe, err := b.Acquire()
		if err != nil || !probe.IsProbe() {
			t.Fatalf("expected probe permit: err=%v probe=%v", err, probe.IsProbe())
		}

		if got := b.State(); got != 2 {
			t.Fatalf("half-open State() = %d, want 2", got)
		}
	})
}

// TestCircuitBreaker_SuccessResetsConsecutiveFailureCounter verifies that a
// successful call resets the consecutive-failure counter. Without the reset,
// non-consecutive failures could trip the breaker threshold when they should not.
func TestCircuitBreaker_SuccessResetsConsecutiveFailureCounter(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	b := NewCircuitBreaker(3, time.Minute, time.Minute, clk.Now)

	// Two failures — not yet at threshold=3.
	p, _ := b.Acquire()
	p.Done(errors.New("fail"))
	p, _ = b.Acquire()
	p.Done(errors.New("fail"))

	// One success must reset the counter to zero.
	p, _ = b.Acquire()
	p.Done(nil)

	// Two more failures — only 2 consecutive since the reset, so the breaker
	// must remain closed (threshold=3 requires 3 consecutive failures).
	p, _ = b.Acquire()
	p.Done(errors.New("fail"))
	p, _ = b.Acquire()
	p.Done(errors.New("fail"))
	if _, err := b.Acquire(); err != nil {
		t.Fatalf("expected closed breaker after 2 consecutive failures (threshold=3): %v", err)
	}

	// A third consecutive failure now trips the threshold.
	p, _ = b.Acquire()
	p.Done(errors.New("fail"))
	if _, err := b.Acquire(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("expected open breaker after 3 consecutive failures: %v", err)
	}
}

// TestCircuitBreaker_NilPermitIsNilSafe verifies that IsProbe() and Done()
// on a nil *Permit are no-ops. Both are called from pipeline defer blocks
// where permit may still be nil if Acquire() was never reached.
func TestCircuitBreaker_NilPermitIsNilSafe(t *testing.T) {
	var p *Permit
	if got := p.IsProbe(); got {
		t.Fatal("nil.IsProbe() = true, want false")
	}
	p.Done(nil)
	p.Done(errors.New("any"))
}

// TestCircuitBreaker_ZeroDurationDefaults verifies that NewCircuitBreaker
// applies the 60-second defaults for zero openDuration and maxProbeDuration,
// and that a nil now func defaults to time.Now.
func TestCircuitBreaker_ZeroDurationDefaults(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	// Both durations are 0 — each defaults to 60 seconds.
	b := NewCircuitBreaker(1, 0, 0, clk.Now)

	p, _ := b.Acquire()
	p.Done(errors.New("fail")) // trips threshold=1 → open

	// At 59s the open-duration default (60s) has not yet elapsed.
	clk.advance(59 * time.Second)
	if _, err := b.Acquire(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("expected open at 59s with 60s default: %v", err)
	}
	// At 61s the breaker transitions to half-open and issues a probe.
	clk.advance(2 * time.Second)
	probe, err := b.Acquire()
	if err != nil || !probe.IsProbe() {
		t.Fatalf("expected probe at 61s (60s default): err=%v probe=%v", err, probe.IsProbe())
	}
}

// TestCircuitBreaker_NilNowDefaultsToTimeNow verifies that passing nil for
// the now func does not panic and produces a functional breaker.
func TestCircuitBreaker_NilNowDefaultsToTimeNow(t *testing.T) {
	b := NewCircuitBreaker(1, time.Minute, time.Minute, nil)
	if b == nil {
		t.Fatal("expected non-nil breaker")
	}
	p, err := b.Acquire()
	if err != nil {
		t.Fatalf("Acquire on fresh breaker: %v", err)
	}
	p.Done(nil) // success should not panic
}
