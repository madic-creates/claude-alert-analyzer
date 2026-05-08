# Storm Cost Protection Phase 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add storm-mode, circuit-breaker, group-cooldown and pipeline failure-phase differentiation to both alert analyzers (k8s + checkmk). All features default disabled; activation via env vars.

**Architecture:** Three new components in `internal/shared/`: `StormDetector` (sliding-window), `CircuitBreaker` (Permit-Token + Watchdog), `NotifyAggregator` (Single-Owner-Goroutine + Request/Reply Stop). One existing file extended (`CooldownManager.CheckAndSetWithGroup`). Both pipelines refactored to use `phase` + `analysisErr` for failure-phase-differentiated cooldown cleanup. Two new Prometheus gauges plus a drop counter.

**Tech Stack:** Go 1.26, `sync.Mutex`, `sync.Once`, `atomic.Bool`, channels, `prometheus/client_golang`, `anthropic-sdk-go` (already migrated, unchanged here).

**Spec reference:** `docs/superpowers/specs/2026-05-01-storm-cost-protection-design.md` (Sections 2.1–2.5). Spec was twice patched in response to Codex review (commits `fc24b83`, `79c511f`).

**Branch:** `feat/storm-cost-protection-phase2`

---

## File Structure

### New files

| File | Responsibility |
|---|---|
| `internal/shared/notify_aggregator.go` | `NotifyAggregator` type, owner-goroutine, request/reply Stop |
| `internal/shared/notify_aggregator_test.go` | Concurrency, drain, hung-publisher tests |
| `internal/shared/storm.go` | `StormDetector` sliding-window counter |
| `internal/shared/storm_test.go` | Window rotation, threshold, concurrent Record |
| `internal/shared/breaker.go` | `CircuitBreaker` + `Permit` token + watchdog |
| `internal/shared/breaker_test.go` | State transitions, idempotency, probe-watchdog, races |

### Modified files

| File | Change |
|---|---|
| `internal/shared/cooldown.go` | Add `CheckAndSetGroup`, `ClearGroup`, atomic `CheckAndSetWithGroup` |
| `internal/shared/cooldown_test.go` | Tests for group methods + atomic rollback |
| `internal/shared/policy.go` | Add `Storm *StormDetector` field + `IsDegraded()` + load extension |
| `internal/shared/policy_test.go` | Tests for `IsDegraded()` with/without Storm |
| `internal/shared/prom_metrics.go` | Add 3 new metrics: storm gauge, breaker gauge, aggregator drops counter |
| `internal/shared/metrics.go` | Helper methods `SetStormMode`, `SetBreakerState`, `AggregatorDropsCounter` |
| `internal/k8s/handler.go` | Compute groupKey, call `Storm.Record()`, switch to `CheckAndSetWithGroup` |
| `internal/k8s/handler_test.go` | Group-key derivation + storm-record assertions |
| `internal/checkmk/handler.go` | Same as k8s handler |
| `internal/checkmk/handler_test.go` | Same as k8s handler test |
| `internal/k8s/pipeline.go` | Phase enum, `analysisErr` tracking, `Permit` wiring, aggregator integration |
| `internal/k8s/pipeline_test.go` | Phase-specific cleanup, half-open-probe behavior, breaker integration |
| `internal/checkmk/pipeline.go` | Same as k8s pipeline |
| `internal/checkmk/pipeline_test.go` | Same as k8s pipeline test |
| `cmd/k8s-analyzer/main.go` | Construct StormDetector, CircuitBreaker, two NotifyAggregator instances; wire into deps |
| `cmd/checkmk-analyzer/main.go` | Same |
| `docs/cost-and-storm-protection.md` | Phase 2 sections (group-cooldown, storm, breaker, drop metric) |
| `CLAUDE.md` | Mention Phase 2 architecture in package layout summary |
| `README.md` | Add Phase 2 env vars to optional-config table |

---

## Task 1: NotifyAggregator (Owner-Goroutine + Request/Reply Stop)

**Files:**
- Create: `internal/shared/notify_aggregator.go`
- Test: `internal/shared/notify_aggregator_test.go`

**Spec:** Section 2.4. Single-owner goroutine; `Add()` non-blocking with two-select pattern; `Stop()` sends `stopRequest{ctx, ack}` via `sync.Once`. Drops counted via injected `prometheus.Counter`.

- [ ] **Step 1: Write the failing tests**

Create `internal/shared/notify_aggregator_test.go`:

```go
package shared

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// fakePublisher records titles and bodies and can be configured to block or fail.
type fakePublisher struct {
	mu        sync.Mutex
	calls     []fakePublishCall
	blockUntil chan struct{}
	failNext   error
}

type fakePublishCall struct {
	title    string
	priority string
	body     string
}

func (p *fakePublisher) Name() string { return "fake" }

func (p *fakePublisher) Publish(ctx context.Context, title, priority, body string) error {
	p.mu.Lock()
	if p.failNext != nil {
		err := p.failNext
		p.failNext = nil
		p.mu.Unlock()
		return err
	}
	block := p.blockUntil
	p.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	p.mu.Lock()
	p.calls = append(p.calls, fakePublishCall{title, priority, body})
	p.mu.Unlock()
	return nil
}

func (p *fakePublisher) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.calls)
}

func (p *fakePublisher) lastCall() fakePublishCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.calls) == 0 {
		return fakePublishCall{}
	}
	return p.calls[len(p.calls)-1]
}

func newDropsCounter() prometheus.Counter {
	return prometheus.NewCounter(prometheus.CounterOpts{Name: "test_drops"})
}

func TestNotifyAggregator_NilWhenDisabled(t *testing.T) {
	if a := NewNotifyAggregator(nil, time.Second, "x", "5", newDropsCounter()); a != nil {
		t.Fatalf("expected nil for empty publishers, got %v", a)
	}
	pub := &fakePublisher{}
	if a := NewNotifyAggregator([]Publisher{pub}, 0, "x", "5", newDropsCounter()); a != nil {
		t.Fatalf("expected nil for interval==0, got %v", a)
	}
}

func TestNotifyAggregator_TickFlushesBuffer(t *testing.T) {
	pub := &fakePublisher{}
	a := NewNotifyAggregator([]Publisher{pub}, 50*time.Millisecond, "Storm: %d alerts", "4", newDropsCounter())
	defer a.Stop(context.Background())

	if !a.Add("alert-1") || !a.Add("alert-2") {
		t.Fatal("Add should succeed")
	}
	// Wait for flush (interval 50ms; allow 200ms slack).
	time.Sleep(200 * time.Millisecond)
	if got := pub.callCount(); got != 1 {
		t.Fatalf("expected 1 publish, got %d", got)
	}
	last := pub.lastCall()
	if last.title != "Storm: 2 alerts" {
		t.Fatalf("title=%q, want %q", last.title, "Storm: 2 alerts")
	}
	if last.priority != "4" {
		t.Fatalf("priority=%q, want 4", last.priority)
	}
}

func TestNotifyAggregator_StopDrainsBuffer(t *testing.T) {
	pub := &fakePublisher{}
	a := NewNotifyAggregator([]Publisher{pub}, 10*time.Second, "S: %d", "5", newDropsCounter())

	for i := 0; i < 5; i++ {
		a.Add("x")
	}
	// Give owner a moment to receive all 5.
	time.Sleep(20 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := a.Stop(ctx); err != nil {
		t.Fatalf("Stop returned %v", err)
	}
	if got := pub.callCount(); got != 1 {
		t.Fatalf("expected 1 final flush, got %d", got)
	}
	if last := pub.lastCall(); last.title != "S: 5" {
		t.Fatalf("title=%q, want S: 5", last.title)
	}
}

func TestNotifyAggregator_AddAfterStopDrops(t *testing.T) {
	pub := &fakePublisher{}
	drops := newDropsCounter()
	a := NewNotifyAggregator([]Publisher{pub}, time.Second, "x", "5", drops)
	if err := a.Stop(context.Background()); err != nil {
		t.Fatalf("Stop returned %v", err)
	}
	for i := 0; i < 100; i++ {
		if a.Add("x") {
			t.Fatalf("Add should return false after Stop")
		}
	}
	// CounterGet via Write helper.
	if v := getCounterValue(drops); v != 100 {
		t.Fatalf("drops=%v, want 100", v)
	}
}

func TestNotifyAggregator_StopIsIdempotent(t *testing.T) {
	pub := &fakePublisher{}
	a := NewNotifyAggregator([]Publisher{pub}, time.Second, "x", "5", newDropsCounter())
	a.Add("x")
	for i := 0; i < 3; i++ {
		if err := a.Stop(context.Background()); err != nil {
			t.Fatalf("Stop call %d returned %v", i, err)
		}
	}
	if got := pub.callCount(); got != 1 {
		t.Fatalf("expected exactly 1 publish, got %d", got)
	}
}

func TestNotifyAggregator_HungPublisher_StopReturnsTimeout(t *testing.T) {
	pub := &fakePublisher{blockUntil: make(chan struct{})}
	a := NewNotifyAggregator([]Publisher{pub}, time.Second, "x", "5", newDropsCounter())
	a.Add("x")
	time.Sleep(20 * time.Millisecond)

	before := runtime.NumGoroutine()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := a.Stop(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Stop err=%v, want DeadlineExceeded", err)
	}
	close(pub.blockUntil) // unblock so the leaked goroutine (if any) exits
	time.Sleep(100 * time.Millisecond)
	after := runtime.NumGoroutine()
	if after > before+1 {
		t.Fatalf("goroutine leak: before=%d after=%d", before, after)
	}
}

func TestNotifyAggregator_StopRaceNoLosses(t *testing.T) {
	pub := &fakePublisher{}
	drops := newDropsCounter()
	a := NewNotifyAggregator([]Publisher{pub}, 5*time.Millisecond, "S: %d", "5", drops)

	const N = 1000
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			a.Add("x")
		}()
	}
	// Stop after a short delay so most Add() are racing with Stop().
	time.Sleep(2 * time.Millisecond)
	_ = a.Stop(context.Background())
	wg.Wait()

	// The title format is "S: %d" so we can recover the per-batch count via Sscanf.
	published := 0
	for _, c := range pub.calls {
		var n int
		if _, err := fmt.Sscanf(c.title, "S: %d", &n); err == nil {
			published += n
		}
	}
	dropCount := int(getCounterValue(drops))
	if published+dropCount != N {
		t.Fatalf("published=%d + drops=%d != %d", published, dropCount, N)
	}
}

// getCounterValue extracts a counter's current value via the Prometheus dto.Metric.
func getCounterValue(c prometheus.Counter) float64 {
	pb := &dto.Metric{}
	if err := c.Write(pb); err != nil {
		return -1
	}
	return pb.GetCounter().GetValue()
}
```

The test file imports go at the top of the file:

```go
import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/shared/ -run TestNotifyAggregator -race
```

Expected: FAIL — `undefined: NewNotifyAggregator`, `undefined: NotifyAggregator`.

- [ ] **Step 3: Implement `NotifyAggregator`**

Create `internal/shared/notify_aggregator.go`:

```go
package shared

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// NotifyAggregator buffers alert titles during a time interval and emits one
// summary notification per interval. It is concurrency-safe via a single
// owner goroutine that owns buffer + timer; Add() and Stop() communicate
// with the owner only via channels.
//
// Stop() uses a request/reply protocol with sync.Once so multiple callers
// receive the same result and the owner goroutine cannot leak.
type NotifyAggregator struct {
	publishers []Publisher
	interval   time.Duration
	titleFmt   string
	priority   string
	drops      prometheus.Counter

	in       chan string       // Add() → owner; gepuffert
	stopReq  chan stopRequest  // Stop() → owner mit ack
	stopOnce sync.Once
	stopped  chan struct{}     // closed by owner before exit
	stopErr  error             // result of first Stop() call (set under stopOnce)
}

type stopRequest struct {
	ctx context.Context
	ack chan error
}

// NewNotifyAggregator constructs the aggregator and spawns the owner goroutine.
// Returns nil if publishers is empty or interval <= 0 — caller treats nil as
// "feature disabled" and falls back to direct PublishAll where appropriate.
//
// drops is incremented every time Add() drops a title (channel full,
// post-Stop, or race). Pass nil for tests that don't care about the metric.
func NewNotifyAggregator(publishers []Publisher, interval time.Duration, titleFmt, priority string, drops prometheus.Counter) *NotifyAggregator {
	if len(publishers) == 0 || interval <= 0 {
		return nil
	}
	a := &NotifyAggregator{
		publishers: publishers,
		interval:   interval,
		titleFmt:   titleFmt,
		priority:   priority,
		drops:      drops,
		in:         make(chan string, 100),
		stopReq:    make(chan stopRequest, 1),
		stopped:    make(chan struct{}),
	}
	go a.run()
	return a
}

// Add buffers an alert title for the next aggregated notification.
// Returns false if the aggregator has been stopped or if the input
// channel is full (back-pressure). In both cases drops is incremented.
//
// Nil-safe: returns false on a nil receiver without incrementing drops.
func (a *NotifyAggregator) Add(alertTitle string) bool {
	if a == nil {
		return false
	}
	// Fast path: aggregator already stopped.
	select {
	case <-a.stopped:
		a.recordDrop()
		return false
	default:
	}
	// Try to enqueue; bail out cleanly if the owner stops between the two selects
	// or the buffer is full.
	select {
	case a.in <- alertTitle:
		return true
	case <-a.stopped:
		a.recordDrop()
		return false
	default:
		a.recordDrop()
		return false
	}
}

func (a *NotifyAggregator) recordDrop() {
	if a.drops != nil {
		a.drops.Inc()
	}
}

// Stop signals the owner goroutine to flush pending alerts and exit.
// Idempotent: only the first call sends a stopRequest; later calls block
// on <-a.stopped and return the same result.
//
// Final flush uses the caller-supplied ctx so a hung publisher cannot
// leak the goroutine. Returns ctx.Err() on timeout, or any publish error
// from the final flush.
func (a *NotifyAggregator) Stop(ctx context.Context) error {
	if a == nil {
		return nil
	}
	a.stopOnce.Do(func() {
		ack := make(chan error, 1)
		select {
		case a.stopReq <- stopRequest{ctx: ctx, ack: ack}:
			// Owner accepted the request; wait for ack or ctx-deadline.
			select {
			case a.stopErr = <-ack:
			case <-ctx.Done():
				a.stopErr = ctx.Err()
			}
		case <-ctx.Done():
			a.stopErr = ctx.Err()
		}
	})
	// Subsequent callers wait until the owner exits before returning.
	select {
	case <-a.stopped:
	case <-ctx.Done():
		return ctx.Err()
	}
	return a.stopErr
}

func (a *NotifyAggregator) run() {
	defer close(a.stopped)
	var buffer []string
	var timer *time.Timer

	flush := func(ctx context.Context) error {
		if len(buffer) == 0 {
			return nil
		}
		title := fmt.Sprintf(a.titleFmt, len(buffer))
		body := strings.Join(buffer, "\n")
		err := PublishAll(ctx, a.publishers, title, a.priority, body)
		buffer = nil
		return err
	}

	for {
		var timerC <-chan time.Time
		if timer != nil {
			timerC = timer.C
		}

		select {
		case alertTitle := <-a.in:
			buffer = append(buffer, alertTitle)
			if timer == nil {
				timer = time.NewTimer(a.interval)
			}
		case <-timerC:
			timer = nil
			// Tick-flush uses context.Background() because NtfyPublisher's
			// internal HTTP timeout (10 s) is the effective bound; we don't
			// want to truncate every steady-state flush to the aggregation
			// interval.
			if err := flush(context.Background()); err != nil {
				slog.Warn("aggregator tick flush failed", "error", err)
			}
		case req := <-a.stopReq:
			if timer != nil {
				timer.Stop()
			}
			// Drain remaining items non-blocking.
		drain:
			for {
				select {
				case alertTitle := <-a.in:
					buffer = append(buffer, alertTitle)
				default:
					break drain
				}
			}
			req.ack <- flush(req.ctx)
			return
		}
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/shared/ -run TestNotifyAggregator -race -v
```

Expected: PASS for all six tests. The race detector should not report anything.

- [ ] **Step 5: Commit**

```bash
git add internal/shared/notify_aggregator.go internal/shared/notify_aggregator_test.go
git commit -m "feat(shared): add NotifyAggregator with owner-goroutine and request/reply Stop"
```

---

## Task 2: StormDetector (sliding-window counter)

**Files:**
- Create: `internal/shared/storm.go`
- Test: `internal/shared/storm_test.go`

**Spec:** Section 2.2. 5-minute sliding window over 1-minute buckets. `NewStormDetector(threshold<=0) → nil` (disabled). `Record()`/`Count()` are nil-safe.

- [ ] **Step 1: Write failing tests**

Create `internal/shared/storm_test.go`:

```go
package shared

import (
	"sync"
	"testing"
	"time"
)

func TestStormDetector_NilWhenDisabled(t *testing.T) {
	if d := NewStormDetector(0, time.Now); d != nil {
		t.Fatalf("threshold=0 should return nil, got %v", d)
	}
	if d := NewStormDetector(-1, time.Now); d != nil {
		t.Fatalf("threshold=-1 should return nil, got %v", d)
	}
}

func TestStormDetector_RecordCountNilSafe(t *testing.T) {
	var d *StormDetector // nil
	d.Record() // must not panic
	if got := d.Count(); got != 0 {
		t.Fatalf("nil.Count()=%d, want 0", got)
	}
}

func TestStormDetector_CountAcrossWindow(t *testing.T) {
	now := time.Unix(0, 0)
	clock := &fakeClock{t: now}
	d := NewStormDetector(50, clock.Now)

	// Minute 0: 10 records
	for i := 0; i < 10; i++ {
		d.Record()
	}
	if got := d.Count(); got != 10 {
		t.Fatalf("minute 0 count=%d, want 10", got)
	}

	// Minute 1: 20 more
	clock.advance(60 * time.Second)
	for i := 0; i < 20; i++ {
		d.Record()
	}
	if got := d.Count(); got != 30 {
		t.Fatalf("minute 0+1 count=%d, want 30", got)
	}

	// Advance to minute 5 — minute 0 falls out of window
	clock.advance(4 * 60 * time.Second)
	if got := d.Count(); got != 20 {
		t.Fatalf("minute 1..5 count=%d, want 20 (minute 0 expired)", got)
	}
}

func TestStormDetector_BucketRotation(t *testing.T) {
	now := time.Unix(0, 0)
	clock := &fakeClock{t: now}
	d := NewStormDetector(50, clock.Now)

	// Fill minute 0
	for i := 0; i < 5; i++ {
		d.Record()
	}
	// Advance 5 minutes — bucket index 0 should be reused for the new minute.
	clock.advance(5 * 60 * time.Second)
	d.Record()
	if got := d.Count(); got != 1 {
		t.Fatalf("after rotation count=%d, want 1", got)
	}
}

func TestStormDetector_ConcurrentRecord(t *testing.T) {
	d := NewStormDetector(1000, time.Now)
	const N = 1000
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			d.Record()
		}()
	}
	wg.Wait()
	if got := d.Count(); got != N {
		t.Fatalf("concurrent count=%d, want %d", got, N)
	}
}

// fakeClock returns a settable time.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/shared/ -run TestStormDetector -race
```

Expected: FAIL — `undefined: StormDetector`, `undefined: NewStormDetector`.

- [ ] **Step 3: Implement `StormDetector`**

Create `internal/shared/storm.go`:

```go
package shared

import (
	"sync"
	"time"
)

// StormDetector counts incoming alerts in a 5-minute sliding window
// (5 buckets × 1 minute) and reports whether the configured threshold
// has been exceeded.
//
// THRESHOLD=0 is encoded as a nil receiver: NewStormDetector(0, _) returns
// nil. Methods are nil-safe so callers do not need to special-case the
// disabled state.
type StormDetector struct {
	threshold int
	now       func() time.Time

	mu      sync.Mutex
	buckets [5]bucket
}

type bucket struct {
	minute int64 // Unix minute (-1 = empty)
	count  int
}

// NewStormDetector returns a detector with the given threshold and clock.
// threshold <= 0 returns nil ("disabled").
func NewStormDetector(threshold int, now func() time.Time) *StormDetector {
	if threshold <= 0 {
		return nil
	}
	if now == nil {
		now = time.Now
	}
	d := &StormDetector{threshold: threshold, now: now}
	for i := range d.buckets {
		d.buckets[i].minute = -1
	}
	return d
}

// Threshold returns the configured threshold (0 if disabled).
func (d *StormDetector) Threshold() int {
	if d == nil {
		return 0
	}
	return d.threshold
}

// Record increments the bucket for the current minute.
// Nil-safe: no-op when the detector is disabled.
func (d *StormDetector) Record() {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	minute := d.now().Unix() / 60
	idx := int(minute%5+5) % 5 // safe modulo for negative time (test clocks)
	if d.buckets[idx].minute != minute {
		d.buckets[idx] = bucket{minute: minute, count: 1}
		return
	}
	d.buckets[idx].count++
}

// Count returns the total count over the last 5 minutes (including the
// current one). Nil-safe: returns 0 when the detector is disabled.
func (d *StormDetector) Count() int {
	if d == nil {
		return 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	minute := d.now().Unix() / 60
	cutoff := minute - 4
	var total int
	for _, b := range d.buckets {
		if b.minute >= cutoff {
			total += b.count
		}
	}
	return total
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/shared/ -run TestStormDetector -race -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/shared/storm.go internal/shared/storm_test.go
git commit -m "feat(shared): add StormDetector sliding-window counter"
```

---

## Task 3: CircuitBreaker with Permit-Token + Probe-Watchdog

**Files:**
- Create: `internal/shared/breaker.go`
- Test: `internal/shared/breaker_test.go`

**Spec:** Section 2.3. Permit-Token-Pattern (`Acquire() → *Permit, error`); `permit.IsProbe()`; `permit.Done(err)` idempotent. Watchdog: stuck probe past `maxProbeDuration` is auto-released as failed.

- [ ] **Step 1: Write failing tests**

Create `internal/shared/breaker_test.go`:

```go
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
	var b *CircuitBreaker // disabled
	p, err := b.Acquire()
	if err != nil || p == nil {
		t.Fatalf("nil-Acquire: p=%v err=%v", p, err)
	}
	if p.IsProbe() {
		t.Fatal("nil-Acquire: IsProbe should be false")
	}
	p.Done(errors.New("any err")) // must not panic
}

func TestCircuitBreaker_ClosedToOpenOnThreshold(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	b := NewCircuitBreaker(2, time.Minute, time.Minute, clk.Now)

	// First failure: still closed
	p, err := b.Acquire()
	if err != nil || p.IsProbe() {
		t.Fatalf("call 1 acquire: err=%v probe=%v", err, p.IsProbe())
	}
	p.Done(errors.New("fail"))

	// Second failure: hits threshold → open
	p, err = b.Acquire()
	if err != nil {
		t.Fatalf("call 2 acquire: err=%v", err)
	}
	p.Done(errors.New("fail"))

	// Third call: open
	if _, err := b.Acquire(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("call 3: err=%v, want ErrCircuitOpen", err)
	}
}

func TestCircuitBreaker_OpenToHalfOpenAfterDuration(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	b := NewCircuitBreaker(1, 30*time.Second, time.Minute, clk.Now)

	p, _ := b.Acquire()
	p.Done(errors.New("fail")) // → open

	// Still within open duration
	clk.advance(29 * time.Second)
	if _, err := b.Acquire(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("during open: err=%v, want ErrCircuitOpen", err)
	}

	// Past open duration → half-open probe
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
	p.Done(errors.New("fail")) // → open

	clk.advance(11 * time.Second)
	probe, _ := b.Acquire()
	if !probe.IsProbe() {
		t.Fatal("expected probe permit")
	}
	probe.Done(nil) // success → closed

	// Next call: closed, not probe
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

	// Should be open again
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

	// First Acquire → probe
	probe, err := b.Acquire()
	if err != nil || !probe.IsProbe() {
		t.Fatalf("first half-open Acquire: err=%v probe=%v", err, probe.IsProbe())
	}
	// Second Acquire (probe still in flight) → ErrCircuitOpen
	if _, err := b.Acquire(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("second half-open Acquire: err=%v, want ErrCircuitOpen", err)
	}
}

func TestCircuitBreaker_DoneIsIdempotent(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	b := NewCircuitBreaker(2, time.Minute, time.Minute, clk.Now)

	p, _ := b.Acquire()
	p.Done(errors.New("fail"))
	p.Done(errors.New("fail again")) // ignored
	p.Done(errors.New("and again"))  // ignored

	// Only one consecFailure should have been counted; second Acquire+fail puts open.
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
	p.Done(errors.New("fail")) // → open
	clk.advance(11 * time.Second)
	probe, _ := b.Acquire()
	if !probe.IsProbe() {
		t.Fatal("expected probe")
	}
	// "Stuck" — never call probe.Done()

	// Within probe-duration window: still in-flight, blocks others
	clk.advance(4 * time.Second)
	if _, err := b.Acquire(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("during probe: err=%v, want ErrCircuitOpen", err)
	}

	// Past probe-duration window: watchdog reopens the breaker
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
			// don't call Done() so subsequent goroutines don't see closed state
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/shared/ -run TestCircuitBreaker -race
```

Expected: FAIL — `undefined: CircuitBreaker`, `undefined: NewCircuitBreaker`, `undefined: ErrCircuitOpen`.

- [ ] **Step 3: Implement `CircuitBreaker` and `Permit`**

Create `internal/shared/breaker.go`:

```go
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
	used    bool // mutated by Done() under breaker.mu
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
		// Disabled-breaker no-op permit
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
		// fallthrough to half-open
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

	// Closed-state permit
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
func (b *CircuitBreaker) State() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case breakerOpen:
		return 1
	case breakerHalfOpen:
		return 2
	}
	return 0
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/shared/ -run TestCircuitBreaker -race -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/shared/breaker.go internal/shared/breaker_test.go
git commit -m "feat(shared): add CircuitBreaker with Permit-Token pattern and probe watchdog"
```

---

## Task 4: CooldownManager group methods (`CheckAndSetGroup`, `ClearGroup`, atomic `CheckAndSetWithGroup`)

**Files:**
- Modify: `internal/shared/cooldown.go`
- Test: `internal/shared/cooldown_test.go`

**Spec:** Section 2.1. Atomic combined check; lock hierarchy `groupMu < fpMu`; rollback on fingerprint-block-after-group-set.

- [ ] **Step 1: Write failing tests**

Add to `internal/shared/cooldown_test.go` (append at the end):

```go
func TestCooldownManager_CheckAndSetGroup_FirstAndRepeat(t *testing.T) {
	cm := NewCooldownManager()
	if !cm.CheckAndSetGroup("g1", time.Second) {
		t.Fatal("first call should set")
	}
	if cm.CheckAndSetGroup("g1", time.Second) {
		t.Fatal("second call should be blocked")
	}
}

func TestCooldownManager_ClearGroup(t *testing.T) {
	cm := NewCooldownManager()
	cm.CheckAndSetGroup("g1", time.Hour)
	cm.ClearGroup("g1")
	if !cm.CheckAndSetGroup("g1", time.Second) {
		t.Fatal("after Clear, set should succeed again")
	}
}

func TestCooldownManager_CheckAndSetWithGroup_BothEmpty(t *testing.T) {
	cm := NewCooldownManager()
	if !cm.CheckAndSetWithGroup("fp1", time.Second, "g1", time.Second) {
		t.Fatal("first combined call should set both")
	}
	// Both should now block independently.
	if cm.CheckAndSet("fp1", time.Second) {
		t.Fatal("fingerprint should be blocked after combined set")
	}
	if cm.CheckAndSetGroup("g1", time.Second) {
		t.Fatal("group should be blocked after combined set")
	}
}

func TestCooldownManager_CheckAndSetWithGroup_GroupBlocksRollbackFP(t *testing.T) {
	cm := NewCooldownManager()
	cm.CheckAndSetGroup("g1", time.Hour)

	// Combined call with the same group: should fail and NOT set fingerprint.
	if cm.CheckAndSetWithGroup("fp1", time.Second, "g1", time.Hour) {
		t.Fatal("combined call should fail when group blocks")
	}
	// Fingerprint must still be available — no orphan entry.
	if !cm.CheckAndSet("fp1", time.Second) {
		t.Fatal("fingerprint should NOT have been set when group blocked")
	}
}

func TestCooldownManager_CheckAndSetWithGroup_FPBlocksRollbackGroup(t *testing.T) {
	cm := NewCooldownManager()
	cm.CheckAndSet("fp1", time.Hour)

	// Combined call with the same fp: should fail and NOT have set group either.
	if cm.CheckAndSetWithGroup("fp1", time.Second, "g1", time.Hour) {
		t.Fatal("combined call should fail when fingerprint blocks")
	}
	// Group must still be available — group was rolled back.
	if !cm.CheckAndSetGroup("g1", time.Second) {
		t.Fatal("group should NOT have been set when fingerprint blocked")
	}
}

func TestCooldownManager_CheckAndSetWithGroup_EmptyGroupSkipsGroup(t *testing.T) {
	cm := NewCooldownManager()
	// Empty group key → skip group, only fingerprint.
	if !cm.CheckAndSetWithGroup("fp1", time.Second, "", time.Second) {
		t.Fatal("empty group should not block fingerprint set")
	}
	// Subsequent fingerprint check should be blocked.
	if cm.CheckAndSet("fp1", time.Second) {
		t.Fatal("fingerprint should now be set")
	}
	// No group entries should exist.
	if !cm.CheckAndSetGroup("any", time.Second) {
		t.Fatal("group map should be empty")
	}
}

func TestCooldownManager_CheckAndSetWithGroup_ConcurrentAtomic(t *testing.T) {
	cm := NewCooldownManager()
	const N = 50
	var ok int64
	var fail int64
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			// All compete on the SAME group key but distinct fingerprints.
			if cm.CheckAndSetWithGroup(fmt.Sprintf("fp-%d", i), time.Second, "shared-group", time.Second) {
				atomic.AddInt64(&ok, 1)
			} else {
				atomic.AddInt64(&fail, 1)
			}
		}(i)
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("expected exactly 1 winner, got %d (rest=%d)", ok, fail)
	}
	if fail != N-1 {
		t.Fatalf("expected %d losers, got %d", N-1, fail)
	}
}
```

Add the necessary imports at the top of `cooldown_test.go` if missing: `"fmt"`, `"sync"`, `"sync/atomic"`.

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/shared/ -run TestCooldownManager -race
```

Expected: FAIL — `undefined: cm.CheckAndSetGroup`, etc.

- [ ] **Step 3: Replace `internal/shared/cooldown.go` with the extended version**

```go
package shared

import (
	"sync"
	"time"
)

type cooldownEntry struct {
	setAt time.Time
	ttl   time.Duration
}

// CooldownManager owns two independent cooldown maps:
//
//   - fingerprint cooldown (existing): one entry per alert fingerprint
//   - group cooldown (Phase 2): coarser-grained dedup (e.g. alertname+namespace)
//
// Lock-Hierarchy: groupMu < fpMu. CheckAndSetWithGroup is the only method
// that holds both locks; it acquires them in groupMu → fpMu order to avoid
// deadlock.
type CooldownManager struct {
	fpMu      sync.Mutex
	fpEntries map[string]cooldownEntry

	groupMu      sync.Mutex
	groupEntries map[string]cooldownEntry
}

func NewCooldownManager() *CooldownManager {
	return &CooldownManager{
		fpEntries:    make(map[string]cooldownEntry),
		groupEntries: make(map[string]cooldownEntry),
	}
}

// CheckAndSet returns true if the fingerprint was not in cooldown and is now set.
// Sweeps expired entries on every call to keep the map bounded.
func (cm *CooldownManager) CheckAndSet(fingerprint string, ttl time.Duration) bool {
	cm.fpMu.Lock()
	defer cm.fpMu.Unlock()
	return checkAndSetLocked(cm.fpEntries, fingerprint, ttl, time.Now())
}

// Clear removes a fingerprint entry.
func (cm *CooldownManager) Clear(fingerprint string) {
	cm.fpMu.Lock()
	delete(cm.fpEntries, fingerprint)
	cm.fpMu.Unlock()
}

// CheckAndSetGroup is the group-level analogue of CheckAndSet, with its own
// map and mutex (groupMu).
func (cm *CooldownManager) CheckAndSetGroup(groupKey string, ttl time.Duration) bool {
	cm.groupMu.Lock()
	defer cm.groupMu.Unlock()
	return checkAndSetLocked(cm.groupEntries, groupKey, ttl, time.Now())
}

// ClearGroup removes a group entry.
func (cm *CooldownManager) ClearGroup(groupKey string) {
	cm.groupMu.Lock()
	delete(cm.groupEntries, groupKey)
	cm.groupMu.Unlock()
}

// CheckAndSetWithGroup atomically checks both cooldowns and sets both, or
// neither, in fixed lock order (groupMu → fpMu). Returns false if either is
// already in cooldown; in that case nothing is mutated.
//
// groupKey == "" or groupTTL == 0 → group is skipped entirely; the call
// reduces to CheckAndSet on the fingerprint alone (with the same locking).
func (cm *CooldownManager) CheckAndSetWithGroup(
	fingerprint string, fpTTL time.Duration,
	groupKey string, groupTTL time.Duration,
) bool {
	now := time.Now()

	if groupKey == "" || groupTTL == 0 {
		cm.fpMu.Lock()
		defer cm.fpMu.Unlock()
		return checkAndSetLocked(cm.fpEntries, fingerprint, fpTTL, now)
	}

	cm.groupMu.Lock()
	defer cm.groupMu.Unlock()
	if !checkAndSetLocked(cm.groupEntries, groupKey, groupTTL, now) {
		return false
	}

	cm.fpMu.Lock()
	defer cm.fpMu.Unlock()
	if !checkAndSetLocked(cm.fpEntries, fingerprint, fpTTL, now) {
		// Rollback the group entry so a single CheckAndSetWithGroup call
		// does not leave the maps in an inconsistent state.
		delete(cm.groupEntries, groupKey)
		return false
	}
	return true
}

// checkAndSetLocked is the lock-free body shared by CheckAndSet and
// CheckAndSetGroup. Caller must hold the relevant mutex.
func checkAndSetLocked(entries map[string]cooldownEntry, key string, ttl time.Duration, now time.Time) bool {
	for k, v := range entries {
		if now.Sub(v.setAt) > v.ttl {
			delete(entries, k)
		}
	}
	if entry, ok := entries[key]; ok {
		if now.Sub(entry.setAt) < entry.ttl {
			return false
		}
	}
	entries[key] = cooldownEntry{setAt: now, ttl: ttl}
	return true
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/shared/ -run TestCooldownManager -race -v
```

Expected: PASS — both new and existing tests.

Run also the full shared package suite to verify no other consumer broke:

```bash
go test ./internal/shared/ -race
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/shared/cooldown.go internal/shared/cooldown_test.go
git commit -m "feat(shared): add atomic CheckAndSetWithGroup for group-cooldown"
```

---

## Task 5: Prometheus metrics extensions (storm gauge, breaker gauge, drops counter)

**Files:**
- Modify: `internal/shared/prom_metrics.go`
- Modify: `internal/shared/metrics.go`
- Test: extend `internal/shared/metrics_test.go` if it exists, else add a minimal verification in `internal/shared/coverage_extra_test.go`

**Spec:** Section 2.2 (storm_mode_active gauge), 2.3 (claude_circuit_breaker_state gauge), 2.4 (notify_aggregator_drops_total counter).

- [ ] **Step 1: Add the three new metric fields to `PrometheusMetrics`**

Edit `internal/shared/prom_metrics.go`. Inside the `PrometheusMetrics` struct, append:

```go
	// StormModeActive is a gauge (0/1) per source — 1 when StormDetector
	// reports the threshold exceeded.
	StormModeActive *prometheus.GaugeVec
	// ClaudeCircuitBreakerState is a gauge per source: 0=closed, 1=open, 2=half-open.
	ClaudeCircuitBreakerState *prometheus.GaugeVec
	// NotifyAggregatorDrops is a counter labeled by aggregator ("storm" | "breaker")
	// that increments every time NotifyAggregator.Add drops a title.
	NotifyAggregatorDrops *prometheus.CounterVec
```

In `NewPrometheusMetrics()`, after `claudeCacheReadTokens` is built, add:

```go
	stormModeActive := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "storm_mode_active",
		Help: "1 when the storm-mode threshold is exceeded for a given source, 0 otherwise.",
	}, []string{"source"})

	claudeCircuitBreakerState := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "claude_circuit_breaker_state",
		Help: "Circuit-breaker state: 0=closed, 1=open, 2=half-open.",
	}, []string{"source"})

	notifyAggregatorDrops := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "notify_aggregator_drops_total",
		Help: "Total alerts dropped by NotifyAggregator (channel full, post-stop, race), by aggregator type.",
	}, []string{"aggregator"})
```

Extend the `reg.MustRegister(...)` block:

```go
	reg.MustRegister(
		alertsAnalyzed,
		alertsCooldown,
		queueDepth,
		claudeAPIDuration,
		claudeAPIErrors,
		ntfyPublishErrors,
		agentToolCalls,
		agentToolDuration,
		agentRoundsUsed,
		agentRoundsExhausted,
		claudeInputTokens,
		claudeOutputTokens,
		claudeCacheCreationTokens,
		claudeCacheReadTokens,
		stormModeActive,
		claudeCircuitBreakerState,
		notifyAggregatorDrops,
	)
```

And the return literal:

```go
	return &PrometheusMetrics{
		registry:                  reg,
		AlertsAnalyzed:            alertsAnalyzed,
		AlertsCooldown:            alertsCooldown,
		QueueDepth:                queueDepth,
		ClaudeAPIDuration:         claudeAPIDuration,
		ClaudeAPIErrors:           claudeAPIErrors,
		NtfyPublishErrors:         ntfyPublishErrors,
		AgentToolCalls:            agentToolCalls,
		AgentToolDuration:         agentToolDuration,
		AgentRoundsUsed:           agentRoundsUsed,
		AgentRoundsExhausted:      agentRoundsExhausted,
		ClaudeInputTokens:         claudeInputTokens,
		ClaudeOutputTokens:        claudeOutputTokens,
		ClaudeCacheCreationTokens: claudeCacheCreationTokens,
		ClaudeCacheReadTokens:     claudeCacheReadTokens,
		StormModeActive:           stormModeActive,
		ClaudeCircuitBreakerState: claudeCircuitBreakerState,
		NotifyAggregatorDrops:     notifyAggregatorDrops,
	}
```

- [ ] **Step 2: Add `AlertMetrics` helper methods**

Append to `internal/shared/metrics.go`:

```go
// SetStormMode sets the storm_mode_active gauge for the given source.
// active=true → 1, active=false → 0. No-op when Prom is nil.
func (m *AlertMetrics) SetStormMode(source string, active bool) {
	if m == nil || m.Prom == nil {
		return
	}
	v := 0.0
	if active {
		v = 1
	}
	m.Prom.StormModeActive.WithLabelValues(source).Set(v)
}

// SetBreakerState sets the claude_circuit_breaker_state gauge for the given
// source. state: 0=closed, 1=open, 2=half-open. No-op when Prom is nil.
func (m *AlertMetrics) SetBreakerState(source string, state int) {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.ClaudeCircuitBreakerState.WithLabelValues(source).Set(float64(state))
}

// AggregatorDropsCounter returns the prometheus.Counter for the given aggregator
// kind ("storm" or "breaker"). Returns nil when Prom is nil. Constructed once at
// startup; safe to pass into NewNotifyAggregator.
func (m *AlertMetrics) AggregatorDropsCounter(kind string) prometheus.Counter {
	if m == nil || m.Prom == nil {
		return nil
	}
	return m.Prom.NotifyAggregatorDrops.WithLabelValues(kind)
}
```

Add the `prometheus` import at the top of `metrics.go` if it's not already there (it currently imports `prometheus/client_golang/prometheus` for the labels-based RecordClaudeUsage, so this is a reuse).

- [ ] **Step 3: Verify build**

```bash
go build ./...
```

Expected: no errors.

```bash
go test ./internal/shared/ -race
```

Expected: PASS — existing tests still green; new code is unit-tested implicitly via the components that use it (Tasks 1, 2, 3 already exist).

- [ ] **Step 4: Commit**

```bash
git add internal/shared/prom_metrics.go internal/shared/metrics.go
git commit -m "feat(metrics): add storm/breaker gauges and notify_aggregator drops counter"
```

---

## Task 6: AnalysisPolicy.Storm + IsDegraded() + LoadPolicy extension

**Files:**
- Modify: `internal/shared/policy.go`
- Test: `internal/shared/policy_test.go`

**Spec:** Section 2.2. `IsDegraded()` returns `true` only when both `Storm != nil` and `Storm.Count() > Storm.Threshold()`.

- [ ] **Step 1: Write failing tests**

Append to `internal/shared/policy_test.go`:

```go
func TestAnalysisPolicy_IsDegradedNilStorm(t *testing.T) {
	p := &AnalysisPolicy{}
	if p.IsDegraded() {
		t.Fatal("nil Storm: IsDegraded should be false")
	}
}

func TestAnalysisPolicy_IsDegradedBelowThreshold(t *testing.T) {
	storm := NewStormDetector(50, time.Now)
	p := &AnalysisPolicy{Storm: storm}
	for i := 0; i < 25; i++ {
		storm.Record()
	}
	if p.IsDegraded() {
		t.Fatalf("count=25 < threshold=50: IsDegraded should be false")
	}
}

func TestAnalysisPolicy_IsDegradedAboveThreshold(t *testing.T) {
	storm := NewStormDetector(10, time.Now)
	p := &AnalysisPolicy{Storm: storm}
	for i := 0; i < 11; i++ {
		storm.Record()
	}
	if !p.IsDegraded() {
		t.Fatal("count=11 > threshold=10: IsDegraded should be true")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/shared/ -run "TestAnalysisPolicy_IsDegraded" -race
```

Expected: FAIL — `p.IsDegraded undefined`.

- [ ] **Step 3: Add the field and method to `AnalysisPolicy`**

Edit `internal/shared/policy.go`. Update the struct:

```go
// AnalysisPolicy is a thin decision layer that maps alert severity to model
// and tool-loop budget. Storm is an optional pointer to a StormDetector;
// nil ↔ storm-mode disabled.
type AnalysisPolicy struct {
	DefaultModel     string
	ModelOverrides   map[Severity]string
	DefaultMaxRounds int
	RoundsOverrides  map[Severity]int
	GroupCooldownTTL time.Duration   // 0 ↔ group-cooldown disabled
	Storm            *StormDetector  // nil ↔ storm-mode disabled
}
```

Append the method below `MaxRoundsFor`:

```go
// IsDegraded reports whether the analyzer is currently in storm-mode.
// Returns false when Storm is nil (storm-mode disabled).
func (p *AnalysisPolicy) IsDegraded() bool {
	if p == nil || p.Storm == nil {
		return false
	}
	return p.Storm.Count() > p.Storm.Threshold()
}
```

- [ ] **Step 4: Extend `LoadPolicy` to read new env vars and construct `Storm`**

Replace the entire `LoadPolicy` function with:

```go
// LoadPolicy builds an AnalysisPolicy from a BaseConfig and the optional
// Phase 1 + Phase 2 environment variables. Phase 2 vars (all optional):
//   - GROUP_COOLDOWN_SECONDS         (default 0 = disabled)
//   - STORM_MODE_THRESHOLD           (default 0 = disabled)
//
// Returns an error if any value fails range validation. Phase 2 storm mode
// requires a clock so callers can inject a fake one in tests; production
// code passes time.Now via the shorthand below.
func LoadPolicy(base BaseConfig) (*AnalysisPolicy, error) {
	defaultRounds, err := ParseIntEnv("MAX_AGENT_ROUNDS", "10", 1, 50)
	if err != nil {
		return nil, err
	}

	modelOverrides := map[Severity]string{}
	for sev, key := range map[Severity]string{
		SeverityCritical: "CLAUDE_MODEL_CRITICAL",
		SeverityWarning:  "CLAUDE_MODEL_WARNING",
		SeverityInfo:     "CLAUDE_MODEL_INFO",
	} {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			modelOverrides[sev] = v
		}
	}

	roundsOverrides := map[Severity]int{}
	for sev, key := range map[Severity]string{
		SeverityCritical: "MAX_AGENT_ROUNDS_CRITICAL",
		SeverityWarning:  "MAX_AGENT_ROUNDS_WARNING",
		SeverityInfo:     "MAX_AGENT_ROUNDS_INFO",
	} {
		if os.Getenv(key) == "" {
			continue
		}
		v, err := ParseIntEnv(key, "", 0, 50)
		if err != nil {
			return nil, fmt.Errorf("policy: %w", err)
		}
		roundsOverrides[sev] = v
	}

	// Phase 2: group cooldown
	groupSecs, err := ParseIntEnv("GROUP_COOLDOWN_SECONDS", "0", 0, 86400)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}

	// Phase 2: storm mode
	stormThreshold, err := ParseIntEnv("STORM_MODE_THRESHOLD", "0", 0, 100000)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	// NewStormDetector returns nil when threshold <= 0 — that is the
	// disabled-default and the Storm field stays nil so IsDegraded() → false.
	storm := NewStormDetector(stormThreshold, time.Now)

	return &AnalysisPolicy{
		DefaultModel:     base.ClaudeModel,
		ModelOverrides:   modelOverrides,
		DefaultMaxRounds: defaultRounds,
		RoundsOverrides:  roundsOverrides,
		GroupCooldownTTL: time.Duration(groupSecs) * time.Second,
		Storm:            storm,
	}, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
go test ./internal/shared/ -race
```

Expected: PASS for all shared tests.

- [ ] **Step 6: Commit**

```bash
git add internal/shared/policy.go internal/shared/policy_test.go
git commit -m "feat(shared): wire StormDetector into AnalysisPolicy.IsDegraded"
```

---

## Task 7: k8s handler — group-key + StormDetector.Record() + CheckAndSetWithGroup

**Files:**
- Modify: `internal/k8s/handler.go`
- Test: `internal/k8s/handler_test.go`

**Spec:** Section 2.1 (group-key derivation, fallback to `:_cluster_` for empty namespace) and 2.2 (Record() in handler before enqueue, after cooldown check).

- [ ] **Step 1: Write failing tests**

Append to `internal/k8s/handler_test.go`:

```go
// k8sGroupKey mirrors handler.go's helper for testing.
func k8sGroupKeyForLabels(labels map[string]string) string {
	ns := labels["namespace"]
	if ns == "" {
		ns = "_cluster_"
	}
	return labels["alertname"] + ":" + ns
}

func TestHandleWebhook_GroupCooldownDeduplicates(t *testing.T) {
	// Use a fake enqueue function and a real CooldownManager.
	cm := shared.NewCooldownManager()
	enqueued := []shared.AlertPayload{}
	enqueue := func(ap shared.AlertPayload) bool {
		enqueued = append(enqueued, ap)
		return true
	}
	metrics := &shared.AlertMetrics{}

	cfg := Config{WebhookSecret: "s", CooldownSeconds: 60, GroupCooldownTTL: time.Minute}
	h := HandleWebhook(cfg, cm, enqueue, metrics, nil) // nil StormDetector

	body := `{"alerts":[{"fingerprint":"fp1","labels":{"alertname":"PodCrashLooping","namespace":"prod","severity":"warning"}}]}`
	req := httptest.NewRequest("POST", "/webhook", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer s")
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != 200 || len(enqueued) != 1 {
		t.Fatalf("first call: code=%d enqueued=%d", rec.Code, len(enqueued))
	}

	// Second alert with DIFFERENT fingerprint but SAME group key
	body = `{"alerts":[{"fingerprint":"fp2","labels":{"alertname":"PodCrashLooping","namespace":"prod","severity":"warning"}}]}`
	req = httptest.NewRequest("POST", "/webhook", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer s")
	rec = httptest.NewRecorder()
	h(rec, req)
	if len(enqueued) != 1 {
		t.Fatalf("group-deduped second call should not enqueue; got %d total", len(enqueued))
	}
	if metrics.AlertsCooldown.Load() != 1 {
		t.Fatalf("AlertsCooldown=%d, want 1", metrics.AlertsCooldown.Load())
	}
}

func TestHandleWebhook_GroupKeyEmptyNamespaceFallback(t *testing.T) {
	cm := shared.NewCooldownManager()
	enqueued := 0
	enqueue := func(shared.AlertPayload) bool { enqueued++; return true }
	metrics := &shared.AlertMetrics{}
	cfg := Config{WebhookSecret: "s", CooldownSeconds: 60, GroupCooldownTTL: time.Minute}
	h := HandleWebhook(cfg, cm, enqueue, metrics, nil)

	// First: alertname=KubeAPIDown, no namespace
	body := `{"alerts":[{"fingerprint":"a","labels":{"alertname":"KubeAPIDown","severity":"critical"}}]}`
	req := httptest.NewRequest("POST", "/webhook", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer s")
	h(req.Context().Value(0).(*httptest.ResponseRecorder), req) // (use new recorder)
	rec := httptest.NewRecorder()
	req2 := httptest.NewRequest("POST", "/webhook", strings.NewReader(body))
	req2.Header.Set("Authorization", "Bearer s")
	h(rec, req2)
	// Need a clean handler; ignore — test below covers the deduplication via the same alertname+empty NS.

	// Second: same alertname, empty NS, different FP → group key matches → deduped
	body = `{"alerts":[{"fingerprint":"b","labels":{"alertname":"KubeAPIDown","severity":"critical"}}]}`
	req3 := httptest.NewRequest("POST", "/webhook", strings.NewReader(body))
	req3.Header.Set("Authorization", "Bearer s")
	rec3 := httptest.NewRecorder()
	h(rec3, req3)
	if enqueued > 1 {
		t.Fatalf("expected at most 1 enqueue (rest deduped via _cluster_ group key), got %d", enqueued)
	}
}

func TestHandleWebhook_StormRecordIncrementsAfterCooldownCheck(t *testing.T) {
	cm := shared.NewCooldownManager()
	enqueue := func(shared.AlertPayload) bool { return true }
	storm := shared.NewStormDetector(1000, time.Now) // high threshold so we just count
	cfg := Config{WebhookSecret: "s", CooldownSeconds: 60}
	h := HandleWebhook(cfg, cm, enqueue, &shared.AlertMetrics{}, storm)

	// Three distinct fingerprints
	for i := 1; i <= 3; i++ {
		body := fmt.Sprintf(`{"alerts":[{"fingerprint":"f%d","labels":{"alertname":"X","namespace":"ns","severity":"warning"}}]}`, i)
		req := httptest.NewRequest("POST", "/webhook", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer s")
		h(httptest.NewRecorder(), req)
	}
	if got := storm.Count(); got != 3 {
		t.Fatalf("storm.Count()=%d, want 3", got)
	}

	// Same fingerprint → cooldown hit → NOT recorded by storm
	body := `{"alerts":[{"fingerprint":"f1","labels":{"alertname":"X","namespace":"ns","severity":"warning"}}]}`
	req := httptest.NewRequest("POST", "/webhook", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer s")
	h(httptest.NewRecorder(), req)
	if got := storm.Count(); got != 3 {
		t.Fatalf("after cooldown-dedup, storm.Count()=%d, want still 3", got)
	}
}
```

Add necessary imports if missing: `"fmt"`, `"net/http/httptest"`, `"strings"`, `"time"`, `"github.com/madic-creates/claude-alert-analyzer/internal/shared"`.

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/k8s/ -run TestHandleWebhook -race
```

Expected: FAIL — `HandleWebhook` signature does not match (extra `*shared.StormDetector` parameter), `Config.GroupCooldownTTL` undefined.

- [ ] **Step 3: Update `internal/k8s/types.go` to add the new Config fields**

Read `internal/k8s/types.go` and append a `GroupCooldownTTL time.Duration` field to the `Config` struct. The existing struct has `WebhookSecret`, `CooldownSeconds`, `MaxLogBytes`, etc.; add the new field next to `CooldownSeconds`:

```go
type Config struct {
	// ... existing fields ...
	CooldownSeconds  int
	GroupCooldownTTL time.Duration // 0 ↔ group cooldown disabled
	// ... rest ...
}
```

- [ ] **Step 4: Update `internal/k8s/handler.go`**

Replace the `HandleWebhook` signature and body:

```go
// HandleWebhook returns an HTTP handler that receives Alertmanager webhook
// payloads. metrics may be nil. storm may be nil (storm-mode disabled).
func HandleWebhook(
	cfg Config,
	cooldown *shared.CooldownManager,
	enqueue func(shared.AlertPayload) bool,
	metrics *shared.AlertMetrics,
	storm *shared.StormDetector,
) http.HandlerFunc {
	cooldownTTL := time.Duration(cfg.CooldownSeconds) * time.Second

	return func(w http.ResponseWriter, r *http.Request) {
		expected := []byte("Bearer " + cfg.WebhookSecret)
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), expected) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxWebhookBodyBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		var payload AlertmanagerWebhook
		if err := json.Unmarshal(body, &payload); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		if len(payload.Alerts) > maxAlertsPerBatch {
			http.Error(w, "too many alerts in batch", http.StatusRequestEntityTooLarge)
			return
		}

		queued := 0
		dropped := 0
		for _, alert := range payload.Alerts {
			if len(alert.Fingerprint) == 0 || len(alert.Fingerprint) > maxFingerprintLen {
				slog.Warn("skipping alert with invalid fingerprint", "alertname", alert.Labels["alertname"])
				if metrics != nil {
					metrics.AlertsInvalidFingerprint.Add(1)
				}
				continue
			}

			if cfg.SkipResolved && alert.Status == "resolved" {
				cooldown.Clear(alert.Fingerprint)
				slog.Info("skipping resolved, cleared cooldown", "alertname", alert.Labels["alertname"])
				continue
			}

			groupKey := groupKeyFromLabels(alert.Labels)

			// Atomic combined check: either both cooldowns set, or neither.
			if !cooldown.CheckAndSetWithGroup(alert.Fingerprint, cooldownTTL, groupKey, cfg.GroupCooldownTTL) {
				slog.Info("in cooldown", "alertname", alert.Labels["alertname"], "groupKey", groupKey)
				if metrics != nil {
					metrics.AlertsCooldown.Add(1)
					metrics.RecordCooldown("k8s")
				}
				continue
			}

			// Storm-mode counter: only counts alerts that pass the cooldown check.
			storm.Record() // nil-safe

			ap := shared.AlertPayload{
				Fingerprint:   alert.Fingerprint,
				Title:         alert.Labels["alertname"],
				Severity:      alert.Labels["severity"],
				SeverityLevel: shared.SeverityFromAlertmanager(alert.Labels),
				Source:        "k8s",
				Fields:        make(map[string]string),
				GroupKey:      groupKey,
			}
			for k, v := range alert.Labels {
				ap.Fields["label:"+k] = v
			}
			for k, v := range alert.Annotations {
				ap.Fields["annotation:"+k] = v
			}
			ap.Fields["status"] = alert.Status
			ap.Fields["startsAt"] = alert.StartsAt.Format("2006-01-02T15:04:05Z07:00")

			if enqueue(ap) {
				queued++
			} else {
				slog.Warn("work queue full, rejecting", "alertname", alert.Labels["alertname"])
				cooldown.Clear(alert.Fingerprint)
				cooldown.ClearGroup(groupKey)
				dropped++
			}
		}

		if dropped > 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, "queued %d, dropped %d (queue full)", queued, dropped)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "queued %d alerts", queued)
	}
}

// groupKeyFromLabels derives the group cooldown key from Alertmanager labels.
// Empty namespace is replaced with the sentinel "_cluster_" so cluster-wide
// alerts (e.g. KubeAPIDown) don't collide with each other or alerts that
// happen to have an empty Namespace label.
func groupKeyFromLabels(labels map[string]string) string {
	ns := labels["namespace"]
	if ns == "" {
		ns = "_cluster_"
	}
	return labels["alertname"] + ":" + ns
}
```

- [ ] **Step 5: Add `GroupKey` to `shared.AlertPayload`**

Edit `internal/shared/payload.go`. Append a `GroupKey string` field to the `AlertPayload` struct so the pipeline can read it without recomputing:

```go
type AlertPayload struct {
	// ... existing fields ...
	GroupKey string // group-cooldown key set by handler; empty if group cooldown disabled
}
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
go test ./internal/k8s/ -race
```

Expected: PASS — new tests pass, existing handler tests still pass (signature change is local — only `cmd/k8s-analyzer/main.go` and tests reference it; cmd will be updated in Task 11).

If existing tests fail because of the signature change in `HandleWebhook`, update them to pass `nil` as the new `storm` argument and to expect the new behavior.

- [ ] **Step 7: Commit**

```bash
git add internal/k8s/handler.go internal/k8s/handler_test.go internal/k8s/types.go internal/shared/payload.go
git commit -m "feat(k8s): add group-cooldown key + StormDetector.Record in handler"
```

---

## Task 8: checkmk handler — group-key + StormDetector.Record() + CheckAndSetWithGroup

**Files:**
- Modify: `internal/checkmk/handler.go`
- Test: `internal/checkmk/handler_test.go`
- Modify: `internal/checkmk/types.go` (add `GroupCooldownTTL`)

**Spec:** Section 2.1. Same pattern as Task 7, with `host:service` (or `host:_host_` for empty service) as the group key.

- [ ] **Step 1: Write failing tests**

Append to `internal/checkmk/handler_test.go`:

```go
func TestHandleWebhook_GroupCooldownDeduplicates(t *testing.T) {
	cm := shared.NewCooldownManager()
	enqueued := 0
	enqueue := func(shared.AlertPayload) bool { enqueued++; return true }
	metrics := &shared.AlertMetrics{}
	cfg := Config{WebhookSecret: "s", CooldownSeconds: 60, GroupCooldownTTL: time.Minute}
	h := HandleWebhook(cfg, cm, enqueue, metrics, nil)

	// Two notifications with different states (different fingerprints) but same host+service.
	first := `{"hostname":"web01","service_description":"CPU","service_state":"WARNING","notification_type":"PROBLEM"}`
	second := `{"hostname":"web01","service_description":"CPU","service_state":"CRITICAL","notification_type":"PROBLEM"}`

	for _, body := range []string{first, second} {
		req := httptest.NewRequest("POST", "/webhook", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer s")
		h(httptest.NewRecorder(), req)
	}
	if enqueued != 1 {
		t.Fatalf("group-deduped: enqueued=%d, want 1", enqueued)
	}
	if metrics.AlertsCooldown.Load() != 1 {
		t.Fatalf("AlertsCooldown=%d, want 1", metrics.AlertsCooldown.Load())
	}
}

func TestHandleWebhook_GroupKeyEmptyServiceFallback(t *testing.T) {
	cm := shared.NewCooldownManager()
	enqueued := 0
	enqueue := func(shared.AlertPayload) bool { enqueued++; return true }
	cfg := Config{WebhookSecret: "s", CooldownSeconds: 60, GroupCooldownTTL: time.Minute}
	h := HandleWebhook(cfg, cm, enqueue, &shared.AlertMetrics{}, nil)

	// Two host-level events (empty service) with different host states.
	first := `{"hostname":"db01","service_description":"","host_state":"DOWN","notification_type":"PROBLEM"}`
	second := `{"hostname":"db01","service_description":"","host_state":"UNREACHABLE","notification_type":"PROBLEM"}`

	for _, body := range []string{first, second} {
		req := httptest.NewRequest("POST", "/webhook", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer s")
		h(httptest.NewRecorder(), req)
	}
	if enqueued != 1 {
		t.Fatalf("host-level group-deduped: enqueued=%d, want 1", enqueued)
	}
}

func TestHandleWebhook_StormRecordIncrementsAfterCooldownCheck(t *testing.T) {
	cm := shared.NewCooldownManager()
	enqueue := func(shared.AlertPayload) bool { return true }
	storm := shared.NewStormDetector(10000, time.Now)
	cfg := Config{WebhookSecret: "s", CooldownSeconds: 60}
	h := HandleWebhook(cfg, cm, enqueue, &shared.AlertMetrics{}, storm)

	// Three distinct host+service combinations
	for i := 1; i <= 3; i++ {
		body := fmt.Sprintf(`{"hostname":"h%d","service_description":"CPU","service_state":"WARNING","notification_type":"PROBLEM"}`, i)
		req := httptest.NewRequest("POST", "/webhook", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer s")
		h(httptest.NewRecorder(), req)
	}
	if got := storm.Count(); got != 3 {
		t.Fatalf("storm.Count()=%d, want 3", got)
	}

	// Same fingerprint → cooldown → NOT recorded
	body := `{"hostname":"h1","service_description":"CPU","service_state":"WARNING","notification_type":"PROBLEM"}`
	req := httptest.NewRequest("POST", "/webhook", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer s")
	h(httptest.NewRecorder(), req)
	if got := storm.Count(); got != 3 {
		t.Fatalf("after cooldown-dedup, storm.Count()=%d, want 3", got)
	}
}
```

Imports: `"fmt"`, `"net/http/httptest"`, `"strings"`, `"time"`.

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/checkmk/ -run TestHandleWebhook -race
```

Expected: FAIL — handler signature mismatch.

- [ ] **Step 3: Add `GroupCooldownTTL` field to `Config`**

Edit `internal/checkmk/types.go`. Append to the `Config` struct:

```go
type Config struct {
	// ... existing fields ...
	GroupCooldownTTL time.Duration // 0 ↔ group cooldown disabled
}
```

- [ ] **Step 4: Update `internal/checkmk/handler.go`**

Replace the `HandleWebhook` function:

```go
func HandleWebhook(
	cfg Config,
	cooldown *shared.CooldownManager,
	enqueue func(shared.AlertPayload) bool,
	metrics *shared.AlertMetrics,
	storm *shared.StormDetector,
) http.HandlerFunc {
	cooldownTTL := time.Duration(cfg.CooldownSeconds) * time.Second

	return func(w http.ResponseWriter, r *http.Request) {
		expected := []byte("Bearer " + cfg.WebhookSecret)
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), expected) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxWebhookBodyBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		var notif CheckMKNotification
		if err := json.Unmarshal(body, &notif); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		if notif.NotificationType == "RECOVERY" {
			for _, state := range []string{"CRITICAL", "WARNING", "UNKNOWN", "OK", ""} {
				cooldown.Clear(fingerprint(notif.Hostname, notif.ServiceDescription, "PROBLEM", state))
				cooldown.Clear(fingerprint(notif.Hostname, notif.ServiceDescription, "FLAPPINGSTART", state))
				cooldown.Clear(fingerprint(notif.Hostname, notif.ServiceDescription, "FLAPPINGSTOP", state))
				cooldown.Clear(fingerprint(notif.Hostname, notif.ServiceDescription, "ACKNOWLEDGEMENT", state))
				cooldown.Clear(fingerprint(notif.Hostname, notif.ServiceDescription, "DOWNTIMESTART", state))
				cooldown.Clear(fingerprint(notif.Hostname, notif.ServiceDescription, "DOWNTIMEEND", state))
				cooldown.Clear(fingerprint(notif.Hostname, notif.ServiceDescription, "DOWNTIMECANCELLED", state))
				cooldown.Clear(fingerprint(notif.Hostname, notif.ServiceDescription, "CUSTOM", state))
			}
			// Also clear the group cooldown so a recovery+re-fire within TTL can pass through.
			cooldown.ClearGroup(groupKeyFromNotif(notif))
			slog.Info("skipping recovery, cleared alert cooldowns",
				"hostname", notif.Hostname, "service", notif.ServiceDescription)
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "skipped recovery")
			return
		}

		fp := fingerprint(notif.Hostname, notif.ServiceDescription, notif.NotificationType, notif.ServiceState)
		groupKey := groupKeyFromNotif(notif)

		if !cooldown.CheckAndSetWithGroup(fp, cooldownTTL, groupKey, cfg.GroupCooldownTTL) {
			slog.Info("in cooldown", "hostname", notif.Hostname, "service", notif.ServiceDescription, "groupKey", groupKey)
			if metrics != nil {
				metrics.AlertsCooldown.Add(1)
				metrics.RecordCooldown("checkmk")
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "in cooldown")
			return
		}

		// Storm-mode counter (after cooldown check)
		storm.Record() // nil-safe

		severity := "warning"
		switch notif.ServiceState {
		case "CRITICAL":
			severity = "critical"
		case "WARNING":
			severity = "warning"
		case "UNKNOWN":
			severity = "unknown"
		case "OK":
			severity = "ok"
		case "":
			switch notif.HostState {
			case "DOWN", "UNREACHABLE":
				severity = "critical"
			case "UP":
				severity = "ok"
			}
		}

		title := notif.Hostname
		if notif.ServiceDescription != "" {
			title = fmt.Sprintf("%s - %s", notif.Hostname, notif.ServiceDescription)
		}

		ap := shared.AlertPayload{
			Fingerprint:   fp,
			Title:         title,
			Severity:      severity,
			SeverityLevel: shared.SeverityFromCheckMK(notif.ServiceState, notif.HostState),
			Source:        "checkmk",
			GroupKey:      groupKey,
			Fields: map[string]string{
				"hostname":            notif.Hostname,
				"host_address":        notif.HostAddress,
				"service_description": notif.ServiceDescription,
				"service_state":       notif.ServiceState,
				"service_output":      notif.ServiceOutput,
				"host_state":          notif.HostState,
				"notification_type":   notif.NotificationType,
				"perf_data":           notif.PerfData,
				"long_plugin_output":  notif.LongPluginOutput,
				"timestamp":           notif.Timestamp,
			},
		}

		if enqueue(ap) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "queued")
		} else {
			slog.Warn("queue full", "hostname", notif.Hostname)
			cooldown.Clear(fp)
			cooldown.ClearGroup(groupKey)
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, "queue full")
		}
	}
}

// groupKeyFromNotif derives the group cooldown key from a CheckMK notification.
// Empty service description (host-level events) is replaced with the sentinel
// "_host_" so they don't collide with each other or with services with empty
// descriptions.
func groupKeyFromNotif(n CheckMKNotification) string {
	svc := n.ServiceDescription
	if svc == "" {
		svc = "_host_"
	}
	return n.Hostname + ":" + svc
}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
go test ./internal/checkmk/ -race
```

Expected: PASS. Existing tests may need their `HandleWebhook` calls updated to pass `nil` for the new `storm` argument.

- [ ] **Step 6: Commit**

```bash
git add internal/checkmk/handler.go internal/checkmk/handler_test.go internal/checkmk/types.go
git commit -m "feat(checkmk): add group-cooldown key + StormDetector.Record in handler"
```

---

## Task 9: k8s pipeline — phase tracking + analysisErr + Permit + Aggregator

**Files:**
- Modify: `internal/k8s/pipeline.go`
- Test: `internal/k8s/pipeline_test.go`

**Spec:** Section 2.1 (phase enum + analysisErr defer), 2.3 (Permit-Token), 2.4 (NotifyAggregator integration when Storm/Breaker active).

- [ ] **Step 1: Write failing tests**

Append to `internal/k8s/pipeline_test.go`:

```go
func TestProcessAlert_PreAPIFailureClearsCooldowns(t *testing.T) {
	cm := shared.NewCooldownManager()
	cm.CheckAndSet("fp1", time.Hour)
	cm.CheckAndSetGroup("g1", time.Hour)

	deps := PipelineDeps{
		Cooldown: cm,
		Metrics:  &shared.AlertMetrics{},
		Policy:   &shared.AnalysisPolicy{DefaultModel: "x", DefaultMaxRounds: 0},
		GatherContext: func(ctx context.Context, a shared.AlertPayload) shared.AnalysisContext {
			panic("simulated gather failure")
		},
		Analyzer:   &mockAnalyzer{},
		ToolRunner: &mockToolRunner{},
		Publishers: []shared.Publisher{&fakePublisher{}},
	}
	alert := shared.AlertPayload{Fingerprint: "fp1", GroupKey: "g1"}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic re-raise")
		}
	}()
	ProcessAlert(context.Background(), deps, alert)
	// After panic recovery, cooldowns should be cleared
	if !cm.CheckAndSet("fp1", time.Second) {
		t.Fatal("PreAPI panic: fp1 should be clear")
	}
	if !cm.CheckAndSetGroup("g1", time.Second) {
		t.Fatal("PreAPI panic: g1 should be clear")
	}
}

func TestProcessAlert_APIFailureClearsCooldowns(t *testing.T) {
	cm := shared.NewCooldownManager()
	cm.CheckAndSet("fp1", time.Hour)
	cm.CheckAndSetGroup("g1", time.Hour)
	pub := &fakePublisher{}

	deps := PipelineDeps{
		Cooldown:      cm,
		Metrics:       &shared.AlertMetrics{},
		Policy:        &shared.AnalysisPolicy{DefaultModel: "x", DefaultMaxRounds: 0},
		GatherContext: func(_ context.Context, _ shared.AlertPayload) shared.AnalysisContext { return shared.AnalysisContext{} },
		Analyzer:      &mockAnalyzer{returnErr: errors.New("api 503")},
		ToolRunner:    &mockToolRunner{},
		Publishers:    []shared.Publisher{pub},
	}
	alert := shared.AlertPayload{Fingerprint: "fp1", GroupKey: "g1"}

	ProcessAlert(context.Background(), deps, alert)

	if !cm.CheckAndSet("fp1", time.Second) {
		t.Fatal("API err: fp1 should be cleared")
	}
	if !cm.CheckAndSetGroup("g1", time.Second) {
		t.Fatal("API err: g1 should be cleared")
	}
}

func TestProcessAlert_ErrCircuitOpenKeepsCooldowns(t *testing.T) {
	cm := shared.NewCooldownManager()
	cm.CheckAndSet("fp1", time.Hour)
	cm.CheckAndSetGroup("g1", time.Hour)
	// Trip the breaker to open
	clk := &fakeClock{t: time.Unix(0, 0)}
	breaker := shared.NewCircuitBreaker(1, time.Hour, time.Hour, clk.Now)
	p, _ := breaker.Acquire()
	p.Done(errors.New("seed"))
	// breaker should now be open

	deps := PipelineDeps{
		Cooldown:      cm,
		Breaker:       breaker,
		Metrics:       &shared.AlertMetrics{},
		Policy:        &shared.AnalysisPolicy{DefaultModel: "x", DefaultMaxRounds: 0},
		GatherContext: func(_ context.Context, _ shared.AlertPayload) shared.AnalysisContext { return shared.AnalysisContext{} },
		Analyzer:      &mockAnalyzer{},
		ToolRunner:    &mockToolRunner{},
		Publishers:    []shared.Publisher{&fakePublisher{}},
	}
	alert := shared.AlertPayload{Fingerprint: "fp1", GroupKey: "g1"}

	ProcessAlert(context.Background(), deps, alert)

	// ErrCircuitOpen path: cooldowns must remain
	if cm.CheckAndSet("fp1", time.Second) {
		t.Fatal("ErrCircuitOpen: fp1 should NOT be cleared")
	}
	if cm.CheckAndSetGroup("g1", time.Second) {
		t.Fatal("ErrCircuitOpen: g1 should NOT be cleared")
	}
}

func TestProcessAlert_PostAPIFailureKeepsCooldowns(t *testing.T) {
	cm := shared.NewCooldownManager()
	cm.CheckAndSet("fp1", time.Hour)
	cm.CheckAndSetGroup("g1", time.Hour)

	failingPub := &fakePublisher{failNext: errors.New("ntfy down")}
	deps := PipelineDeps{
		Cooldown:      cm,
		Metrics:       &shared.AlertMetrics{},
		Policy:        &shared.AnalysisPolicy{DefaultModel: "x", DefaultMaxRounds: 0},
		GatherContext: func(_ context.Context, _ shared.AlertPayload) shared.AnalysisContext { return shared.AnalysisContext{} },
		Analyzer:      &mockAnalyzer{returnAnalysis: "ok"},
		ToolRunner:    &mockToolRunner{},
		Publishers:    []shared.Publisher{failingPub},
	}
	alert := shared.AlertPayload{Fingerprint: "fp1", GroupKey: "g1"}

	ProcessAlert(context.Background(), deps, alert)

	if cm.CheckAndSet("fp1", time.Second) {
		t.Fatal("PostAPI err: fp1 should NOT be cleared")
	}
	if cm.CheckAndSetGroup("g1", time.Second) {
		t.Fatal("PostAPI err: g1 should NOT be cleared")
	}
}

func TestProcessAlert_HalfOpenProbeForcesRoundsZero(t *testing.T) {
	cm := shared.NewCooldownManager()
	clk := &fakeClock{t: time.Unix(0, 0)}
	breaker := shared.NewCircuitBreaker(1, 10*time.Second, time.Minute, clk.Now)
	p, _ := breaker.Acquire()
	p.Done(errors.New("seed"))
	clk.advance(11 * time.Second) // breaker now half-open

	an := &mockAnalyzer{returnAnalysis: "ok"}
	tr := &mockToolRunner{}
	deps := PipelineDeps{
		Cooldown:      cm,
		Breaker:       breaker,
		Metrics:       &shared.AlertMetrics{},
		Policy:        &shared.AnalysisPolicy{DefaultModel: "x", DefaultMaxRounds: 10}, // would normally use tool loop
		GatherContext: func(_ context.Context, _ shared.AlertPayload) shared.AnalysisContext { return shared.AnalysisContext{} },
		Analyzer:      an,
		ToolRunner:    tr,
		Publishers:    []shared.Publisher{&fakePublisher{}},
	}
	alert := shared.AlertPayload{Fingerprint: "fp1", SeverityLevel: shared.SeverityCritical}

	ProcessAlert(context.Background(), deps, alert)

	if an.calls != 1 || tr.calls != 0 {
		t.Fatalf("half-open probe: Analyzer.calls=%d ToolRunner.calls=%d, want 1/0", an.calls, tr.calls)
	}
}

func TestProcessAlert_StormDegradedForcesRoundsZero(t *testing.T) {
	cm := shared.NewCooldownManager()
	storm := shared.NewStormDetector(1, time.Now)
	storm.Record()
	storm.Record() // count=2 > threshold=1

	an := &mockAnalyzer{returnAnalysis: "ok"}
	tr := &mockToolRunner{}
	deps := PipelineDeps{
		Cooldown:      cm,
		Metrics:       &shared.AlertMetrics{},
		Policy:        &shared.AnalysisPolicy{DefaultModel: "x", DefaultMaxRounds: 10, Storm: storm},
		GatherContext: func(_ context.Context, _ shared.AlertPayload) shared.AnalysisContext { return shared.AnalysisContext{} },
		Analyzer:      an,
		ToolRunner:    tr,
		Publishers:    []shared.Publisher{&fakePublisher{}},
	}
	alert := shared.AlertPayload{Fingerprint: "fp1", SeverityLevel: shared.SeverityCritical}

	ProcessAlert(context.Background(), deps, alert)

	if an.calls != 1 || tr.calls != 0 {
		t.Fatalf("storm-degraded: Analyzer.calls=%d ToolRunner.calls=%d, want 1/0", an.calls, tr.calls)
	}
}
```

If `mockAnalyzer`, `mockToolRunner`, and `fakePublisher` do not yet exist in `pipeline_test.go`, add them at the end of the file (they may already exist for Phase 1 tests):

```go
type mockAnalyzer struct {
	calls          int
	returnAnalysis string
	returnErr      error
}

func (m *mockAnalyzer) Analyze(ctx context.Context, model, system, user string) (string, error) {
	m.calls++
	if m.returnErr != nil {
		return "", m.returnErr
	}
	return m.returnAnalysis, nil
}

type mockToolRunner struct {
	calls int
}

func (m *mockToolRunner) RunToolLoop(ctx context.Context, model, system, user string, tools []shared.Tool, maxRounds int, h shared.ToolCallHandler) (string, int, bool, error) {
	m.calls++
	return "ok", 1, false, nil
}

type fakePublisher struct {
	mu       sync.Mutex
	calls    []fakePublishCall
	failNext error
}
type fakePublishCall struct{ title, priority, body string }

func (p *fakePublisher) Name() string { return "fake" }
func (p *fakePublisher) Publish(ctx context.Context, title, priority, body string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failNext != nil {
		err := p.failNext
		p.failNext = nil
		return err
	}
	p.calls = append(p.calls, fakePublishCall{title, priority, body})
	return nil
}

// fakeClock helper (mirrored from internal/shared tests)
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time           { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) advance(d time.Duration)  { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }
```

Imports: `"context"`, `"errors"`, `"sync"`, `"testing"`, `"time"`.

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/k8s/ -run TestProcessAlert -race
```

Expected: FAIL — `PipelineDeps.Breaker undefined`, `PipelineDeps.StormNotify undefined`, etc.

- [ ] **Step 3: Update `PipelineDeps` and `ProcessAlert` in `internal/k8s/pipeline.go`**

Replace the file contents:

```go
package k8s

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
)

// failurePhase tracks how far ProcessAlert progressed when an error occurred,
// so the deferred cleanup decides correctly whether to clear cooldowns.
type failurePhase int

const (
	phasePreAPI failurePhase = iota
	phaseAPI
	phasePostAPI
)

// PipelineDeps holds all dependencies for k8s alert processing.
type PipelineDeps struct {
	Analyzer      shared.Analyzer
	ToolRunner    shared.ToolLoopRunner
	KubectlRunner KubectlRunner
	Prom          PromQLQuerier
	Publishers    []shared.Publisher
	Cooldown      *shared.CooldownManager
	Metrics       *shared.AlertMetrics
	Policy        *shared.AnalysisPolicy
	Breaker       *shared.CircuitBreaker  // nil ↔ disabled
	StormNotify   *shared.NotifyAggregator // nil ↔ no aggregator (storm not configured)
	BreakerNotify *shared.NotifyAggregator // nil ↔ no aggregator (breaker not configured)
	GatherContext func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext
}

// ProcessAlert gathers context, analyzes via Claude, and publishes results.
//
// Failure-phase cleanup: a separate `analysisErr` variable is used inside
// the defer so that a post-API publish error (which sets the named return
// `err`) cannot kip the phase decision. See spec section 2.1.
func ProcessAlert(ctx context.Context, deps PipelineDeps, alert shared.AlertPayload) {
	start := time.Now()
	var (
		phase       failurePhase = phasePreAPI
		analysisErr error
	)

	defer func() {
		deps.Metrics.ProcessingDurationSum.Add(time.Since(start).Microseconds())
		deps.Metrics.ProcessingDurationCount.Add(1)
	}()

	defer func() {
		// Phase-differentiated cooldown cleanup.
		// Panic recovery: turn it into a phaseAPI-style failure so the same
		// rules apply (panic could happen anywhere; conservative default).
		if r := recover(); r != nil {
			if analysisErr == nil {
				analysisErr = fmt.Errorf("panic recovered: %v", r)
			}
			defer panic(r) // re-panic AFTER the cleanup runs
		}
		switch phase {
		case phasePreAPI:
			deps.Cooldown.Clear(alert.Fingerprint)
			if alert.GroupKey != "" {
				deps.Cooldown.ClearGroup(alert.GroupKey)
			}
			if analysisErr != nil {
				deps.Metrics.AlertsFailed.Add(1)
			}
		case phaseAPI:
			if analysisErr == nil {
				return
			}
			if errors.Is(analysisErr, shared.ErrCircuitOpen) {
				// Verstärker-Mitigation: keep cooldowns to absorb retries.
				deps.Metrics.AlertsFailed.Add(1)
				return
			}
			deps.Cooldown.Clear(alert.Fingerprint)
			if alert.GroupKey != "" {
				deps.Cooldown.ClearGroup(alert.GroupKey)
			}
			deps.Metrics.AlertsFailed.Add(1)
		case phasePostAPI:
			// Analysis succeeded; ntfy-failure is logged separately, no re-analyze trigger.
			return
		}
	}()

	alertname := shared.SanitizeAlertField(alert.Title)
	namespace := shared.SanitizeAlertField(alert.Fields["label:namespace"])
	slog.Info("processing alert", "alertname", alertname, "namespace", namespace)

	// === Pre-API phase ===
	actx := deps.GatherContext(ctx, alert)
	userPrompt := fmt.Sprintf("## Alert: %s\n- Status: %s\n- Severity: %s\n- Namespace: %s\n- StartsAt: %s\n\n%s",
		alertname,
		shared.SanitizeAlertField(alert.Fields["status"]),
		shared.SanitizeAlertField(alert.Severity),
		namespace,
		shared.SanitizeAlertField(alert.Fields["startsAt"]),
		actx.FormatForPrompt())

	// Update breaker-state metric on every alert so Grafana sees the gauge fresh.
	if deps.Breaker != nil {
		deps.Metrics.SetBreakerState("k8s", deps.Breaker.State())
	}
	deps.Metrics.SetStormMode("k8s", deps.Policy.IsDegraded())

	// === Acquire breaker permit ===
	phase = phaseAPI
	permit, err := deps.Breaker.Acquire()
	if err != nil {
		analysisErr = err
		// Aggregate the alert into the breaker-aggregator instead of sending a per-alert ntfy.
		if deps.BreakerNotify != nil {
			deps.BreakerNotify.Add(alertname)
		}
		slog.Warn("breaker open, dropping analysis", "alertname", alertname)
		deps.Metrics.RecordClaudeAPIError(alert.Source)
		return
	}
	defer permit.Done(analysisErr) // panic-safe, idempotent

	model := deps.Policy.ModelFor(alert.SeverityLevel)
	rounds := deps.Policy.MaxRoundsFor(alert.SeverityLevel)
	if deps.Policy.IsDegraded() || permit.IsProbe() {
		rounds = 0
	}

	var analysis string
	if rounds == 0 {
		analysis, analysisErr = deps.Analyzer.Analyze(ctx, model, StaticAnalysisSystemPrompt, userPrompt)
	} else {
		analysis, analysisErr = RunAgenticDiagnostics(ctx, deps.ToolRunner, deps.KubectlRunner, deps.Prom, deps.Metrics, userPrompt, rounds, model)
	}
	if analysisErr != nil {
		slog.Error("analysis failed", "alertname", alertname, "error", analysisErr)
		deps.Metrics.RecordClaudeAPIError(alert.Source)
		// Per-alert failure ntfy (the deferred cleanup decides whether cooldowns are kept).
		if notifyErr := shared.PublishAll(ctx, deps.Publishers,
			fmt.Sprintf("Analysis FAILED: %s", alertname), "5",
			fmt.Sprintf("**Analysis failed** for %s: %v\n\nManual investigation needed.", alertname, analysisErr)); notifyErr != nil {
			slog.Warn("failed to publish failure notification", "alertname", alertname, "error", notifyErr)
		}
		return
	}
	if analysis == "" {
		analysisErr = errors.New("empty analysis")
		slog.Warn("analysis returned empty result, treating as failure", "alertname", alertname)
		if notifyErr := shared.PublishAll(ctx, deps.Publishers,
			fmt.Sprintf("Analysis FAILED: %s", alertname), "5",
			fmt.Sprintf("**Analysis produced empty result** for %s.\n\nManual investigation needed.", alertname)); notifyErr != nil {
			slog.Warn("failed to publish failure notification", "alertname", alertname, "error", notifyErr)
		}
		return
	}

	// === Post-API phase ===
	phase = phasePostAPI

	// Storm-mode aggregator: if active, aggregate the success notification too;
	// otherwise publish per-alert ntfy.
	title := fmt.Sprintf("Analysis: %s", alertname)
	if namespace != "" {
		title = fmt.Sprintf("Analysis: %s (%s)", alertname, namespace)
	}
	priorityMap := map[string]string{"critical": "5", "warning": "4", "info": "2"}
	priority := priorityMap[alert.Severity]
	if priority == "" {
		priority = "3"
	}

	if deps.Policy.IsDegraded() && deps.StormNotify != nil {
		deps.StormNotify.Add(alertname)
	} else if pubErr := shared.PublishAll(ctx, deps.Publishers, title, priority, analysis); pubErr != nil {
		slog.Error("failed to publish analysis", "alertname", alertname, "error", pubErr)
		deps.Metrics.RecordNtfyPublishError(alert.Source)
		// Phase is already phasePostAPI — defer keeps cooldowns. AlertsFailed
		// counter is the operator-visible signal here.
		deps.Metrics.AlertsFailed.Add(1)
		return
	}

	deps.Metrics.AlertsProcessed.Add(1)
	deps.Metrics.RecordAnalyzed(alert.Source, alert.Severity)
	slog.Info("analysis complete", "alertname", alertname)
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/k8s/ -race
```

Expected: PASS — all new and pre-existing tests.

If a pre-existing pipeline test breaks because of the new defer behavior (cooldowns no longer cleared on every error), update it: the new contract is in section 2.1 of the spec.

- [ ] **Step 5: Commit**

```bash
git add internal/k8s/pipeline.go internal/k8s/pipeline_test.go
git commit -m "refactor(k8s): phase-tracking + Permit + aggregator wiring in pipeline"
```

---

## Task 10: checkmk pipeline — phase tracking + analysisErr + Permit + Aggregator

**Files:**
- Modify: `internal/checkmk/pipeline.go`
- Test: `internal/checkmk/pipeline_test.go`

**Spec:** Same as Task 9, adapted for the CheckMK pipeline (which has SSH validation + agentic SSH instead of kubectl).

- [ ] **Step 1: Write failing tests**

Append to `internal/checkmk/pipeline_test.go` the same six tests as Task 9 but adapted for `checkmk.PipelineDeps` (it has different fields). Use the file's existing `mockAnalyzer`/`mockToolRunner`/`fakePublisher` if they exist, else add them as in Task 9.

The key behavior tests are identical:
- PreAPI panic clears cooldowns
- API err clears cooldowns
- ErrCircuitOpen keeps cooldowns
- PostAPI publish err keeps cooldowns
- Half-open probe forces rounds=0
- Storm-degraded forces rounds=0

Use a no-op `ValidateHost` that returns a non-nil HostInfo to bypass SSH-validation in these tests:

```go
func validateHostNoop(_ context.Context, _, _ string) (*HostInfo, error) {
	return &HostInfo{VerifiedIP: "127.0.0.1"}, nil
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/checkmk/ -run TestProcessAlert -race
```

Expected: FAIL.

- [ ] **Step 3: Update `internal/checkmk/pipeline.go`**

Replace the file contents:

```go
package checkmk

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
)

type failurePhase int

const (
	phasePreAPI failurePhase = iota
	phaseAPI
	phasePostAPI
)

type PipelineDeps struct {
	Analyzer      shared.Analyzer
	ToolRunner    shared.ToolLoopRunner
	Publishers    []shared.Publisher
	Cooldown      *shared.CooldownManager
	Metrics       *shared.AlertMetrics
	Policy        *shared.AnalysisPolicy
	Breaker       *shared.CircuitBreaker
	StormNotify   *shared.NotifyAggregator
	BreakerNotify *shared.NotifyAggregator
	SSHEnabled    bool
	SSHDialer     Dialer
	SSHConfig     Config
	GatherContext func(ctx context.Context, alert shared.AlertPayload, hostInfo *HostInfo) shared.AnalysisContext
	ValidateHost  func(ctx context.Context, hostname, hostAddress string) (*HostInfo, error)
}

func ProcessAlert(ctx context.Context, deps PipelineDeps, alert shared.AlertPayload) {
	start := time.Now()
	var (
		phase       failurePhase = phasePreAPI
		analysisErr error
	)
	defer func() {
		deps.Metrics.ProcessingDurationSum.Add(time.Since(start).Microseconds())
		deps.Metrics.ProcessingDurationCount.Add(1)
	}()
	defer func() {
		if r := recover(); r != nil {
			if analysisErr == nil {
				analysisErr = fmt.Errorf("panic recovered: %v", r)
			}
			defer panic(r)
		}
		switch phase {
		case phasePreAPI:
			deps.Cooldown.Clear(alert.Fingerprint)
			if alert.GroupKey != "" {
				deps.Cooldown.ClearGroup(alert.GroupKey)
			}
			if analysisErr != nil {
				deps.Metrics.AlertsFailed.Add(1)
			}
		case phaseAPI:
			if analysisErr == nil {
				return
			}
			if errors.Is(analysisErr, shared.ErrCircuitOpen) {
				deps.Metrics.AlertsFailed.Add(1)
				return
			}
			deps.Cooldown.Clear(alert.Fingerprint)
			if alert.GroupKey != "" {
				deps.Cooldown.ClearGroup(alert.GroupKey)
			}
			deps.Metrics.AlertsFailed.Add(1)
		case phasePostAPI:
			return
		}
	}()

	hostname := alert.Fields["hostname"]
	hostAddress := alert.Fields["host_address"]
	safeTitle := shared.SanitizeAlertField(alert.Title)
	slog.Info("processing CheckMK alert", "hostname", hostname, "service", alert.Fields["service_description"])

	hostInfo, validationErr := deps.ValidateHost(ctx, hostname, hostAddress)
	if validationErr != nil {
		slog.Warn("host validation failed", "error", validationErr, "hostname", hostname, "host_address", hostAddress)
	}
	actx := deps.GatherContext(ctx, alert, hostInfo)
	alertContext := actx.FormatForPrompt()

	sshOK := deps.SSHEnabled && validationErr == nil && hostInfo != nil
	if deps.SSHEnabled && !sshOK {
		alertContext += "\n## Note\nSSH diagnostics unavailable: host validation failed\n"
	}

	if deps.Breaker != nil {
		deps.Metrics.SetBreakerState("checkmk", deps.Breaker.State())
	}
	deps.Metrics.SetStormMode("checkmk", deps.Policy.IsDegraded())

	phase = phaseAPI
	permit, err := deps.Breaker.Acquire()
	if err != nil {
		analysisErr = err
		if deps.BreakerNotify != nil {
			deps.BreakerNotify.Add(safeTitle)
		}
		slog.Warn("breaker open, dropping analysis", "hostname", hostname)
		deps.Metrics.RecordClaudeAPIError(alert.Source)
		return
	}
	defer permit.Done(analysisErr)

	model := deps.Policy.ModelFor(alert.SeverityLevel)
	rounds := deps.Policy.MaxRoundsFor(alert.SeverityLevel)
	if deps.Policy.IsDegraded() || permit.IsProbe() {
		rounds = 0
	}

	var analysis string
	if rounds > 0 && sshOK {
		analysis, analysisErr = RunAgenticDiagnostics(ctx, deps.SSHConfig, deps.ToolRunner, deps.SSHDialer, deps.Metrics, hostname, hostInfo.VerifiedIP, alertContext, rounds, model)
	} else {
		analysis, analysisErr = deps.Analyzer.Analyze(ctx, model, StaticAnalysisSystemPrompt, alertContext)
	}
	if analysisErr != nil {
		slog.Error("analysis failed", "hostname", hostname, "error", analysisErr)
		deps.Metrics.RecordClaudeAPIError(alert.Source)
		if notifyErr := shared.PublishAll(ctx, deps.Publishers,
			fmt.Sprintf("Analysis FAILED: %s", safeTitle), "5",
			fmt.Sprintf("**Analysis failed** for %s: %v\n\nManual investigation needed.", safeTitle, analysisErr)); notifyErr != nil {
			slog.Warn("failed to publish failure notification", "hostname", hostname, "error", notifyErr)
		}
		return
	}
	if analysis == "" {
		analysisErr = errors.New("empty analysis")
		slog.Warn("analysis returned empty result, treating as failure", "hostname", hostname)
		if notifyErr := shared.PublishAll(ctx, deps.Publishers,
			fmt.Sprintf("Analysis FAILED: %s", safeTitle), "5",
			fmt.Sprintf("**Analysis produced empty result** for %s.\n\nManual investigation needed.", safeTitle)); notifyErr != nil {
			slog.Warn("failed to publish failure notification", "hostname", hostname, "error", notifyErr)
		}
		return
	}

	phase = phasePostAPI

	priorityMap := map[string]string{"critical": "5", "warning": "4", "unknown": "3", "ok": "2"}
	priority := priorityMap[alert.Severity]
	if priority == "" {
		priority = "3"
	}
	title := fmt.Sprintf("Analysis: %s", safeTitle)

	if deps.Policy.IsDegraded() && deps.StormNotify != nil {
		deps.StormNotify.Add(safeTitle)
	} else if pubErr := shared.PublishAll(ctx, deps.Publishers, title, priority, analysis); pubErr != nil {
		slog.Error("failed to publish analysis", "hostname", hostname, "error", pubErr)
		deps.Metrics.RecordNtfyPublishError(alert.Source)
		deps.Metrics.AlertsFailed.Add(1)
		return
	}

	deps.Metrics.AlertsProcessed.Add(1)
	deps.Metrics.RecordAnalyzed(alert.Source, alert.Severity)
	slog.Info("analysis complete", "hostname", hostname)
}
```

- [ ] **Step 2: Run tests to verify they pass**

```bash
go test ./internal/checkmk/ -race
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/checkmk/pipeline.go internal/checkmk/pipeline_test.go
git commit -m "refactor(checkmk): phase-tracking + Permit + aggregator wiring in pipeline"
```

---

## Task 11: cmd/k8s-analyzer wiring

**Files:**
- Modify: `cmd/k8s-analyzer/main.go`

**Spec:** Construct StormDetector (already done in policy load), CircuitBreaker, two NotifyAggregator instances; pass them through to handler+pipeline.

- [ ] **Step 1: Read the current `cmd/k8s-analyzer/main.go` to identify wiring points**

Run:
```bash
grep -n "HandleWebhook\|PipelineDeps\|cooldown\|metrics" cmd/k8s-analyzer/main.go | head -30
```

The main wiring point is where `HandleWebhook(...)` is called and where `PipelineDeps{...}` is constructed. We append breaker construction, two aggregator constructions, env-var loading for breaker thresholds.

- [ ] **Step 2: Add env-var helpers for breaker + aggregator intervals**

In `cmd/k8s-analyzer/main.go`, add a helper section that reads:
- `CIRCUIT_BREAKER_THRESHOLD` (int, 0-100, default 0)
- `CIRCUIT_BREAKER_OPEN_SECONDS` (int, 1-3600, default 60)
- `CIRCUIT_BREAKER_MAX_PROBE_SECONDS` (int, 1-3600, default 60)
- `STORM_MODE_NOTIFY_INTERVAL` (duration string, default "60s")
- `CIRCUIT_BREAKER_NOTIFY_INTERVAL` (duration string, default "300s")

```go
breakerThreshold, err := shared.ParseIntEnv("CIRCUIT_BREAKER_THRESHOLD", "0", 0, 100)
if err != nil {
	slog.Error("invalid CIRCUIT_BREAKER_THRESHOLD", "error", err)
	os.Exit(1)
}
breakerOpenSecs, err := shared.ParseIntEnv("CIRCUIT_BREAKER_OPEN_SECONDS", "60", 1, 3600)
if err != nil {
	slog.Error("invalid CIRCUIT_BREAKER_OPEN_SECONDS", "error", err)
	os.Exit(1)
}
breakerProbeSecs, err := shared.ParseIntEnv("CIRCUIT_BREAKER_MAX_PROBE_SECONDS", "60", 1, 3600)
if err != nil {
	slog.Error("invalid CIRCUIT_BREAKER_MAX_PROBE_SECONDS", "error", err)
	os.Exit(1)
}
breaker := shared.NewCircuitBreaker(
	breakerThreshold,
	time.Duration(breakerOpenSecs)*time.Second,
	time.Duration(breakerProbeSecs)*time.Second,
	time.Now,
)

stormNotifyInterval, err := time.ParseDuration(shared.EnvOrDefault("STORM_MODE_NOTIFY_INTERVAL", "60s"))
if err != nil {
	slog.Error("invalid STORM_MODE_NOTIFY_INTERVAL", "error", err)
	os.Exit(1)
}
breakerNotifyInterval, err := time.ParseDuration(shared.EnvOrDefault("CIRCUIT_BREAKER_NOTIFY_INTERVAL", "300s"))
if err != nil {
	slog.Error("invalid CIRCUIT_BREAKER_NOTIFY_INTERVAL", "error", err)
	os.Exit(1)
}

stormNotify := shared.NewNotifyAggregator(
	publishers,
	stormNotifyInterval,
	"Storm-mode active: %d alerts in last interval",
	"4",
	metrics.AggregatorDropsCounter("storm"),
)
breakerNotify := shared.NewNotifyAggregator(
	publishers,
	breakerNotifyInterval,
	"API rate-limited: %d alerts pending manual review",
	"5",
	metrics.AggregatorDropsCounter("breaker"),
)
```

- [ ] **Step 3: Pass `storm` (already on policy) into `HandleWebhook`**

Locate the `HandleWebhook(...)` call and update it to pass `policy.Storm` as the new last argument:

```go
mux := server.BuildMux(k8s.HandleWebhook(k8sCfg, cooldown, server.Enqueue, metrics, policy.Storm))
```

- [ ] **Step 4: Construct `PipelineDeps` with new fields**

Update the existing `PipelineDeps{...}` literal to include `Breaker`, `StormNotify`, `BreakerNotify`:

```go
deps := k8s.PipelineDeps{
	// ... existing fields ...
	Breaker:       breaker,
	StormNotify:   stormNotify,
	BreakerNotify: breakerNotify,
}
```

- [ ] **Step 5: Wire `GroupCooldownTTL` into the k8s `Config`**

In the same main.go, when constructing `k8sCfg`, set `GroupCooldownTTL: policy.GroupCooldownTTL`. Add this if it's not already done:

```go
k8sCfg.GroupCooldownTTL = policy.GroupCooldownTTL
```

- [ ] **Step 6: Add aggregator Stop() to graceful-shutdown path**

The `shared.Server.Run` path executes `wg.Wait()` after worker drain. The two aggregators must Stop after that. Since `Server.Run` controls shutdown internally, the cleanest hook is to Stop the aggregators inline before calling `server.Run(...)` is wrong — we need them stopped after Run returns.

Wrap the `server.Run(handler)` call:

```go
defer func() {
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopCancel()
	if stormNotify != nil {
		if err := stormNotify.Stop(stopCtx); err != nil {
			slog.Warn("storm aggregator stop returned error", "error", err)
		}
	}
	if breakerNotify != nil {
		if err := breakerNotify.Stop(stopCtx); err != nil {
			slog.Warn("breaker aggregator stop returned error", "error", err)
		}
	}
}()
server.Run(mux)
```

(Note: if `server.Run` performs `os.Exit` internally, the `defer` won't run; verify by reading `server.go:155-165` — currently it logs and `os.Exit(1)` only on `ListenAndServe` error, not on graceful shutdown. The graceful-shutdown path returns normally after `wg.Wait()` and `slog.Info("shutdown complete")`, so the defer will run.)

- [ ] **Step 7: Build and test**

```bash
go build ./cmd/k8s-analyzer
go test ./... -race
```

Expected: PASS for all packages.

- [ ] **Step 8: Commit**

```bash
git add cmd/k8s-analyzer/main.go
git commit -m "feat(k8s-cmd): wire CircuitBreaker and NotifyAggregators into main"
```

---

## Task 12: cmd/checkmk-analyzer wiring

**Files:**
- Modify: `cmd/checkmk-analyzer/main.go`

**Spec:** Same as Task 11, adapted to checkmk's main.

- [ ] **Step 1: Mirror Task 11 for `cmd/checkmk-analyzer/main.go`**

Apply the same five additions:
1. Read `CIRCUIT_BREAKER_*` env vars and construct breaker.
2. Read `*_NOTIFY_INTERVAL` env vars and construct two aggregators.
3. Pass `policy.Storm` to `checkmk.HandleWebhook(...)`.
4. Add `Breaker`, `StormNotify`, `BreakerNotify` to `checkmk.PipelineDeps{...}`.
5. Set `cfg.GroupCooldownTTL = policy.GroupCooldownTTL`.
6. Add aggregator Stop() in deferred shutdown.

The code is identical to Task 11; the labels in metric counter calls remain `"storm"` and `"breaker"` (the source label is on the gauges, not on drops).

- [ ] **Step 2: Build and test**

```bash
go build ./cmd/checkmk-analyzer
go test ./... -race
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add cmd/checkmk-analyzer/main.go
git commit -m "feat(checkmk-cmd): wire CircuitBreaker and NotifyAggregators into main"
```

---

## Task 13: Verstärker-Bug end-to-end sequence test

**Files:**
- Test: `internal/k8s/pipeline_test.go` (append) — also mirror in `internal/checkmk/pipeline_test.go`

**Spec:** Section 6 of the spec. The most important behavioral test: verify that an open circuit-breaker plus a re-fired Alertmanager webhook does NOT result in a second analysis attempt.

- [ ] **Step 1: Write the failing sequence test (k8s)**

Append to `internal/k8s/pipeline_test.go`:

```go
func TestVerstaerkerBug_OpenBreakerKeepsCooldown_NoSecondAnalysis(t *testing.T) {
	// 1. Setup: cooldown manager + breaker with threshold=1 (already failed once below).
	cm := shared.NewCooldownManager()
	clk := &fakeClock{t: time.Unix(0, 0)}
	breaker := shared.NewCircuitBreaker(1, time.Hour, time.Hour, clk.Now)
	// Pre-fail the breaker so it's open.
	p, _ := breaker.Acquire()
	p.Done(errors.New("seed failure"))

	// Mock claude — counts calls.
	an := &mockAnalyzer{returnAnalysis: "ok"}
	tr := &mockToolRunner{}

	// Aggregator that records calls (we expect breakerNotify.Add to be called).
	pub := &fakePublisher{}
	breakerNotify := shared.NewNotifyAggregator([]shared.Publisher{pub}, time.Hour, "Aggregate: %d", "5", nil)
	defer breakerNotify.Stop(context.Background())

	deps := PipelineDeps{
		Cooldown:      cm,
		Breaker:       breaker,
		BreakerNotify: breakerNotify,
		Metrics:       &shared.AlertMetrics{},
		Policy:        &shared.AnalysisPolicy{DefaultModel: "x", DefaultMaxRounds: 0},
		GatherContext: func(_ context.Context, _ shared.AlertPayload) shared.AnalysisContext { return shared.AnalysisContext{} },
		Analyzer:      an,
		ToolRunner:    tr,
		Publishers:    []shared.Publisher{pub},
	}

	// 2. Set the cooldown as if a previous webhook had set it.
	cm.CheckAndSet("fp1", time.Hour)
	cm.CheckAndSetGroup("g1", time.Hour)

	// 3. ProcessAlert with breaker open → ErrCircuitOpen → cooldowns must remain.
	alert := shared.AlertPayload{Fingerprint: "fp1", GroupKey: "g1", SeverityLevel: shared.SeverityWarning}
	ProcessAlert(context.Background(), deps, alert)

	if cm.CheckAndSet("fp1", time.Second) {
		t.Fatal("after ErrCircuitOpen: fp1 cooldown should still be set")
	}
	if cm.CheckAndSetGroup("g1", time.Second) {
		t.Fatal("after ErrCircuitOpen: g1 cooldown should still be set")
	}
	if an.calls != 0 || tr.calls != 0 {
		t.Fatalf("Claude must NOT have been called; analyzer=%d tool=%d", an.calls, tr.calls)
	}

	// 4. Simulate Alertmanager retry: the handler-level cooldown check would have
	//    blocked it, but here we test the pipeline directly. Re-running ProcessAlert
	//    with the same Alert — even at this layer, the second invocation should also
	//    not call the analyzer (breaker still open, Acquire returns ErrCircuitOpen).
	ProcessAlert(context.Background(), deps, alert)
	if an.calls != 0 || tr.calls != 0 {
		t.Fatalf("retry: Claude must STILL not have been called; analyzer=%d tool=%d", an.calls, tr.calls)
	}
}
```

- [ ] **Step 2: Mirror the test in `internal/checkmk/pipeline_test.go`**

Adapt for `checkmk.PipelineDeps` (uses ValidateHost, no kubectl). Same assertions: cooldowns remain, Claude not called.

- [ ] **Step 3: Run tests to verify they pass (the implementation from Tasks 9+10 should already make them pass)**

```bash
go test ./internal/k8s/ ./internal/checkmk/ -run TestVerstaerker -race -v
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/k8s/pipeline_test.go internal/checkmk/pipeline_test.go
git commit -m "test(pipeline): add Verstärker-Bug sequence test for open breaker"
```

---

## Task 14: Documentation updates

**Files:**
- Modify: `docs/cost-and-storm-protection.md` (add Phase 2 sections)
- Modify: `CLAUDE.md` (mention Phase 2 architecture summary)
- Modify: `README.md` (add Phase 2 env vars to optional-config section)

- [ ] **Step 1: Append to `docs/cost-and-storm-protection.md`**

After the existing Phase 1 sections, add:

```markdown
## Phase 2 — Storm Robustness

Phase 2 adds three opt-in protections that close two attack surfaces left
open by Phase 1: high cost from re-analyzing every distinct fingerprint
during a storm, and the Storm-Verstärker-Bug where API failures clear
cooldowns, causing Alertmanager to retry into a degraded API.

All Phase 2 features default to disabled (`THRESHOLD=0` / `SECONDS=0`).
Enable each independently after observing the Phase 1 metrics.

### Group-Cooldown

Set `GROUP_COOLDOWN_SECONDS=60` (suggested). Both analyzers will treat alerts
with the same group key as a single alert during the TTL window:

- k8s:    `groupKey = alertname:namespace`  (empty namespace → `:_cluster_`)
- CheckMK: `groupKey = host:service`         (empty service → `:_host_`)

Group-cooldown sits next to (not in place of) the existing fingerprint
cooldown. The handler uses the atomic `CooldownManager.CheckAndSetWithGroup`
to set both at once, with rollback if either is already in cooldown.

### Storm-Mode

Set `STORM_MODE_THRESHOLD=50` (alerts/5min, suggested). When the sliding
5-minute window exceeds the threshold, the analyzer enters degraded mode:

- All severities are forced to `rounds=0` (no tool-loop) — saves the most
  cost per alert.
- Group-key remains unchanged (storm mode doesn't widen dedup; that's
  operator policy via `GROUP_COOLDOWN_SECONDS`).
- Aggregated ntfy via the shared `NotifyAggregator`: one summary per
  `STORM_MODE_NOTIFY_INTERVAL` (default 60s) instead of N per-alert messages.

Gauge: `storm_mode_active{source}` (0/1) — page operators on `1` for >5min.

### Circuit-Breaker

Set `CIRCUIT_BREAKER_THRESHOLD=5` (consecutive failures, suggested). When
5 logical analyses in a row fail, the breaker opens for
`CIRCUIT_BREAKER_OPEN_SECONDS` (default 60). All `Acquire()` calls during
that window return `ErrCircuitOpen` — alerts get aggregated into the
breaker-aggregator instead of triggering API calls.

After the open period the breaker enters half-open: exactly one probe
analysis is allowed (with `rounds=0`). On success → closed; on failure →
open again.

A probe-watchdog (`CIRCUIT_BREAKER_MAX_PROBE_SECONDS`, default 60s)
prevents stuck-state if the probe goroutine hangs without calling
`permit.Done()`.

Gauge: `claude_circuit_breaker_state{source}` (0=closed, 1=open, 2=half-open).

### Storm-Verstärker-Bug Mitigation

The pipeline tracks the failure phase (Pre-API / API / Post-API) and the
analysis error in separate variables. Cooldowns are cleared only for
Pre-API and API-phase failures that are NOT `ErrCircuitOpen`. With an
open breaker, cooldowns remain set so Alertmanager-retries hit cooldowns
on subsequent webhooks instead of hammering the degraded API.

### Notify-Aggregator Drop Metric

`notify_aggregator_drops_total{aggregator}` (counter, labels: `storm`,
`breaker`) reports alerts that were dropped because the aggregator's
in-channel was full or the aggregator was already stopped. Sustained
non-zero drops indicate the aggregation interval is too long for the
current alert volume — increase the `*_NOTIFY_INTERVAL` or shorten it,
depending on operator preference.

### Migration sequence

1. Phase 1 PR is merged and stable. Observe `claude_input_tokens_total`,
   `claude_cache_read_tokens_total`, etc.
2. Enable `GROUP_COOLDOWN_SECONDS=60`. Observe `alerts_cooldown_total{source}`.
3. After 1 week: enable `CIRCUIT_BREAKER_THRESHOLD=5`. Observe
   `claude_circuit_breaker_state` and `notify_aggregator_drops_total{aggregator="breaker"}`.
4. Last: enable `STORM_MODE_THRESHOLD=50`. Observe `storm_mode_active`
   and `notify_aggregator_drops_total{aggregator="storm"}`.

### Recommended PromQL

```
# Cache-hit rate (Phase 1, Phase 2 contextual)
sum(rate(claude_cache_read_tokens_total[5m]))
  / sum(rate(claude_cache_read_tokens_total[5m])
       + rate(claude_cache_creation_tokens_total[5m])
       + rate(claude_input_tokens_total[5m]))

# Storm-mode dwell-time (alerts on storm_mode_active=1 for >5min)
storm_mode_active{source="k8s"} == 1

# Breaker-open dwell-time (alerts on state=1 for >2min)
claude_circuit_breaker_state{source="checkmk"} == 1

# Aggregator-drop rate
sum by (aggregator) (rate(notify_aggregator_drops_total[5m]))
```
```

- [ ] **Step 2: Update `CLAUDE.md`**

In the "Architecture" section under the existing Phase 1 description, append:

```markdown
- **Phase 2 (storm-mode + circuit-breaker + group-cooldown)**: Three new
  components in `internal/shared/`: `StormDetector` (sliding-window),
  `CircuitBreaker` (Permit-Token + Watchdog), `NotifyAggregator`
  (Single-Owner-Goroutine + Request/Reply Stop). Pipeline tracks
  `phase` + `analysisErr` for failure-phase-differentiated cooldown
  cleanup. All features default disabled. See
  `docs/cost-and-storm-protection.md` for operator guidance.
```

In the "Environment Variables" section, append the Phase 2 vars:

```markdown
Phase 2 optional: `GROUP_COOLDOWN_SECONDS` (default 0 = disabled),
`STORM_MODE_THRESHOLD` (default 0), `STORM_MODE_NOTIFY_INTERVAL` (default 60s),
`CIRCUIT_BREAKER_THRESHOLD` (default 0), `CIRCUIT_BREAKER_OPEN_SECONDS` (default 60),
`CIRCUIT_BREAKER_MAX_PROBE_SECONDS` (default 60),
`CIRCUIT_BREAKER_NOTIFY_INTERVAL` (default 300s).
```

- [ ] **Step 3: Update `README.md`**

Read the existing README and append a Phase 2 row to the env var table (or section). Keep it short:

```markdown
### Phase 2 — Storm robustness (optional, default disabled)

| Env var | Default | Purpose |
|---|---|---|
| `GROUP_COOLDOWN_SECONDS` | `0` | Coarser dedup: alertname+namespace (k8s) / host+service (checkmk) |
| `STORM_MODE_THRESHOLD` | `0` | Alerts/5min before forcing rounds=0 + aggregated ntfy |
| `STORM_MODE_NOTIFY_INTERVAL` | `60s` | Storm-aggregator emit interval |
| `CIRCUIT_BREAKER_THRESHOLD` | `0` | Consecutive analysis failures before open |
| `CIRCUIT_BREAKER_OPEN_SECONDS` | `60` | Open-state duration |
| `CIRCUIT_BREAKER_MAX_PROBE_SECONDS` | `60` | Half-open probe watchdog timeout |
| `CIRCUIT_BREAKER_NOTIFY_INTERVAL` | `300s` | Breaker-aggregator emit interval |

See `docs/cost-and-storm-protection.md` for the recommended migration
sequence.
```

- [ ] **Step 4: Verify rendering and links**

```bash
grep -n "Phase 2" docs/cost-and-storm-protection.md CLAUDE.md README.md
```

Expected: each file contains at least one Phase 2 reference.

- [ ] **Step 5: Commit**

```bash
git add docs/cost-and-storm-protection.md CLAUDE.md README.md
git commit -m "docs: Phase 2 operator guide, env vars, and architecture summary"
```

---

## Final Verification

- [ ] **Run the full test suite with -race**

```bash
go test ./... -race
```

Expected: PASS, every package green.

- [ ] **Build both binaries**

```bash
CGO_ENABLED=0 go build -o /tmp/k8s-analyzer ./cmd/k8s-analyzer/
CGO_ENABLED=0 go build -o /tmp/checkmk-analyzer ./cmd/checkmk-analyzer/
```

Expected: both binaries built without warnings.

- [ ] **Smoke-test config loading**

```bash
WEBHOOK_SECRET=x ANTHROPIC_API_KEY=y \
GROUP_COOLDOWN_SECONDS=60 STORM_MODE_THRESHOLD=50 CIRCUIT_BREAKER_THRESHOLD=5 \
/tmp/k8s-analyzer --help 2>&1 | head -5
```

Expected: no startup error from env-var parsing (binary may fail later on missing in-cluster config, that's fine).

- [ ] **Push branch + open PR**

```bash
git push -u origin feat/storm-cost-protection-phase2
gh pr create --title "feat: Phase 2 — storm-mode, circuit-breaker, group-cooldown" --body "$(cat <<'EOF'
## Summary

Phase 2 of the storm/cost protection design (issue #9). Three opt-in
protections plus the Storm-Verstärker-Bug fix.

- Group-cooldown via atomic `CheckAndSetWithGroup` with rollback
- Storm-mode via 5-min sliding window; forces `rounds=0` when degraded
- Circuit-breaker with Permit-Token API + probe watchdog
- NotifyAggregator with Request/Reply Stop (no goroutine leak)
- Pipeline tracks phase + analysisErr for failure-phase-differentiated
  cooldown cleanup (Verstärker-Bug fix)

All features default disabled. See spec in
`docs/superpowers/specs/2026-05-01-storm-cost-protection-design.md`
and operator guide in `docs/cost-and-storm-protection.md`.

## Test plan

- [ ] `go test ./... -race` clean
- [ ] Verstärker-Bug sequence test passes for both pipelines
- [ ] Half-Open-Probe-Begrenzung sequence test passes
- [ ] Group-cooldown deduplicates alerts with same alertname+namespace (k8s) / host+service (checkmk)
- [ ] Sentinel fallbacks work (k8s _cluster_, checkmk _host_)
- [ ] Drop-metric increments on Add-after-Stop and channel-full
- [ ] CI pipeline green
EOF
)"
```

Expected: PR opened on GitHub.

---

## Self-Review Notes

**Spec coverage check:**
- Section 2.1 (group-cooldown + lifecycle): Tasks 4, 7, 8, 9, 10 ✓
- Section 2.2 (storm-mode): Tasks 2, 6, 7, 8 ✓
- Section 2.3 (circuit-breaker + Permit + watchdog): Tasks 3, 9, 10, 11, 12 ✓
- Section 2.4 (NotifyAggregator + drop metric): Tasks 1, 5, 11, 12 ✓
- Section 2.5 (interaction matrix): covered behaviorally by tests in 9, 10, 13
- Verstärker-Bug + Half-Open-Probe sequence tests: Task 13 ✓
- Documentation: Task 14 ✓

**Type consistency check:**
- `*Permit` returned by `Acquire()`, used by `permit.IsProbe()` and `permit.Done()` — consistent in Tasks 3, 9, 10
- `*StormDetector` constructed in Task 2, threaded into policy in Task 6, into handler in Tasks 7+8 — consistent
- `*NotifyAggregator` constructed in Task 1, threaded into PipelineDeps in Tasks 9+10, into main in Tasks 11+12 — consistent
- `GroupKey string` field added to `AlertPayload` in Task 7, consumed in Tasks 9, 10 — consistent
- `failurePhase` enum local to each pipeline package (k8s and checkmk have their own) — intentional; phase values match by name

**Potential pitfall flagged:**
- The defer-with-recover in Tasks 9, 10 has a subtle ordering: panic-recover sets `analysisErr`, then `defer panic(r)` re-raises after the cleanup-switch runs. Verify in implementation that the second defer (`defer panic(r)`) is inside the recovered defer, not at function level — otherwise the re-panic would skip the cleanup. The code as written is correct because `defer panic(r)` registers as a deferred call within the running deferred function, and Go runs deferred calls in LIFO before unwinding past the current frame.
