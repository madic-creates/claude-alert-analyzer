package shared

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

// aggFakePublisher records titles and bodies and can be configured to block or fail.
// (Renamed from `fakePublisher` to avoid collision with the existing test fake in ntfy_test.go.)
type aggFakePublisher struct {
	mu         sync.Mutex
	calls      []aggFakePublishCall
	blockUntil chan struct{}
	failNext   error
}

type aggFakePublishCall struct {
	title    string
	priority string
	body     string
}

func (p *aggFakePublisher) Name() string { return "fake" }

func (p *aggFakePublisher) Publish(ctx context.Context, title, priority, body string) error {
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
	p.calls = append(p.calls, aggFakePublishCall{title, priority, body})
	p.mu.Unlock()
	return nil
}

func (p *aggFakePublisher) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.calls)
}

func (p *aggFakePublisher) lastCall() aggFakePublishCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.calls) == 0 {
		return aggFakePublishCall{}
	}
	return p.calls[len(p.calls)-1]
}

func newDropsCounter() prometheus.Counter {
	return prometheus.NewCounter(prometheus.CounterOpts{Name: "test_drops"})
}

// getCounterValue extracts a counter's current value via the Prometheus dto.Metric.
func getCounterValue(c prometheus.Counter) float64 {
	pb := &dto.Metric{}
	if err := c.Write(pb); err != nil {
		return -1
	}
	return pb.GetCounter().GetValue()
}

func TestNotifyAggregator_NilWhenDisabled(t *testing.T) {
	if a := NewNotifyAggregator(nil, time.Second, "x", "5", newDropsCounter()); a != nil {
		t.Fatalf("expected nil for empty publishers, got %v", a)
	}
	pub := &aggFakePublisher{}
	if a := NewNotifyAggregator([]Publisher{pub}, 0, "x", "5", newDropsCounter()); a != nil {
		t.Fatalf("expected nil for interval==0, got %v", a)
	}
}

func TestNotifyAggregator_TickFlushesBuffer(t *testing.T) {
	pub := &aggFakePublisher{}
	a := NewNotifyAggregator([]Publisher{pub}, 50*time.Millisecond, "Storm: %d alerts", "4", newDropsCounter())
	defer a.Stop(context.Background())

	if !a.Add("alert-1") || !a.Add("alert-2") {
		t.Fatal("Add should succeed")
	}
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
	pub := &aggFakePublisher{}
	a := NewNotifyAggregator([]Publisher{pub}, 10*time.Second, "S: %d", "5", newDropsCounter())

	for i := 0; i < 5; i++ {
		a.Add("x")
	}
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
	pub := &aggFakePublisher{}
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
	if v := getCounterValue(drops); v != 100 {
		t.Fatalf("drops=%v, want 100", v)
	}
}

func TestNotifyAggregator_StopIsIdempotent(t *testing.T) {
	pub := &aggFakePublisher{}
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
	pub := &aggFakePublisher{blockUntil: make(chan struct{})}
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

// TestNotifyAggregator_StopConcurrentCallersAgree verifies that 50 concurrent
// Stop() callers all see the same outcome under the race detector. The
// sync.Once memory-model guarantees that the f-body's writes to stopErr
// happen-before any Do call returns, so a follow-on read after <-stopped
// is safe — but only as long as no goroutine reads stopErr without going
// through Once.Do first. This test locks down that contract.
func TestNotifyAggregator_StopConcurrentCallersAgree(t *testing.T) {
	pub := &aggFakePublisher{}
	a := NewNotifyAggregator([]Publisher{pub}, time.Second, "x", "5", newDropsCounter())
	a.Add("seed")

	const N = 50
	var wg sync.WaitGroup
	wg.Add(N)
	results := make([]error, N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			results[i] = a.Stop(context.Background())
		}(i)
	}
	wg.Wait()

	// All callers must agree.
	for i := 1; i < N; i++ {
		if results[i] != results[0] {
			t.Fatalf("caller %d got %v, caller 0 got %v — disagreement", i, results[i], results[0])
		}
	}
	// The seed alert should have been published once via the final flush.
	if got := pub.callCount(); got != 1 {
		t.Fatalf("expected 1 publish, got %d", got)
	}
}

func TestNotifyAggregator_TickFlushPublisherFailureCountsDrops(t *testing.T) {
	pub := &aggFakePublisher{failNext: errors.New("ntfy down")}
	drops := newDropsCounter()
	a := NewNotifyAggregator([]Publisher{pub}, 30*time.Millisecond, "S: %d", "5", drops)
	defer a.Stop(context.Background())

	for i := 0; i < 7; i++ {
		a.Add("x")
	}
	// Wait for the tick (30ms interval; 200ms slack).
	time.Sleep(200 * time.Millisecond)

	if v := getCounterValue(drops); v != 7 {
		t.Fatalf("publisher-error drops=%v, want 7", v)
	}
}

// publishBlocker is a Publisher that closes started on its first Publish call
// and then blocks until unblock is closed. Used to freeze the owner goroutine
// inside flush() so the in-channel can be filled to capacity deterministically.
type publishBlocker struct {
	started chan struct{}
	unblock chan struct{}
	once    sync.Once
}

func (p *publishBlocker) Name() string { return "blocker" }
func (p *publishBlocker) Publish(ctx context.Context, _, _, _ string) error {
	p.once.Do(func() { close(p.started) })
	select {
	case <-p.unblock:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TestNotifyAggregator_AddChannelFullDrops covers the default branch in Add's
// second select — the overflow path when a.in is at capacity. The owner
// goroutine is frozen inside Publish() so nothing drains a.in while we fill it
// to notifyAggregatorBufferSize; the next Add must hit the default drop.
func TestNotifyAggregator_AddChannelFullDrops(t *testing.T) {
	pub := &publishBlocker{
		started: make(chan struct{}),
		unblock: make(chan struct{}),
	}
	drops := newDropsCounter()
	// 50 ms interval: short enough to fire quickly, long enough that the owner
	// reads the seed into its buffer before the tick fires.
	a := NewNotifyAggregator([]Publisher{pub}, 50*time.Millisecond, "S: %d", "5", drops)

	// Seed one item so the tick flush is non-empty and Publish() is called.
	if !a.Add("seed") {
		t.Fatal("seed Add should succeed")
	}

	// Wait for the tick to fire and the owner to enter Publish() (blocked).
	select {
	case <-pub.started:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("publisher never started — tick did not fire in time")
	}

	// Owner is now blocked inside Publish(). Fill a.in to its full capacity.
	for i := 0; i < notifyAggregatorBufferSize; i++ {
		if !a.Add(fmt.Sprintf("alert-%d", i)) {
			t.Fatalf("Add %d should succeed while channel has capacity", i)
		}
	}

	// This Add must hit the default (channel-full) drop path.
	if a.Add("overflow") {
		t.Fatal("Add when channel is full must return false")
	}
	if v := getCounterValue(drops); v != 1 {
		t.Fatalf("drops=%v, want 1 (channel-full drop)", v)
	}

	// Unblock the publisher and stop cleanly.
	close(pub.unblock)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = a.Stop(ctx)
}

func TestNotifyAggregator_StopRaceNoLosses(t *testing.T) {
	pub := &aggFakePublisher{}
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
	time.Sleep(2 * time.Millisecond)
	_ = a.Stop(context.Background())
	wg.Wait()

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
