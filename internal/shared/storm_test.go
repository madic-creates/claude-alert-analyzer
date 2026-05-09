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

// TestNewStormDetector_NilClock verifies that passing nil as the clock
// falls back to time.Now without panicking. This covers the previously-
// untested `if now == nil { now = time.Now }` branch in NewStormDetector.
func TestNewStormDetector_NilClock(t *testing.T) {
	d := NewStormDetector(10, nil)
	if d == nil {
		t.Fatal("expected non-nil detector for threshold=10, nil clock")
	}
	d.Record() // must not panic using the real clock
	if c := d.Count(); c < 0 {
		t.Errorf("Count() = %d, want >= 0", c)
	}
}

func TestStormDetector_RecordCountNilSafe(t *testing.T) {
	var d *StormDetector // nil
	d.Record()           // must not panic
	if got := d.Count(); got != 0 {
		t.Fatalf("nil.Count()=%d, want 0", got)
	}
}

func TestStormDetector_CountAcrossWindow(t *testing.T) {
	now := time.Unix(0, 0)
	clock := &fakeClock{t: now}
	d := NewStormDetector(50, clock.Now)

	for i := 0; i < 10; i++ {
		d.Record()
	}
	if got := d.Count(); got != 10 {
		t.Fatalf("minute 0 count=%d, want 10", got)
	}

	clock.advance(60 * time.Second)
	for i := 0; i < 20; i++ {
		d.Record()
	}
	if got := d.Count(); got != 30 {
		t.Fatalf("minute 0+1 count=%d, want 30", got)
	}

	clock.advance(4 * 60 * time.Second)
	if got := d.Count(); got != 20 {
		t.Fatalf("minute 1..5 count=%d, want 20 (minute 0 expired)", got)
	}
}

func TestStormDetector_BucketRotation(t *testing.T) {
	now := time.Unix(0, 0)
	clock := &fakeClock{t: now}
	d := NewStormDetector(50, clock.Now)

	for i := 0; i < 5; i++ {
		d.Record()
	}
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
