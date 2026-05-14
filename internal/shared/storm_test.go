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

// TestStormDetector_NegativeUnixTime exercises the `+5` guard in Record's bucket
// index formula: `int(minute%5+5) % 5`. Without the `+5`, Go's sign-preserving
// modulo returns -1 for minute=-1 and `d.buckets[-1]` would panic with an
// out-of-range index. The guard is documented in storm.go but was previously
// untested because all other tests start at time.Unix(0, 0) (minute 0).
func TestStormDetector_NegativeUnixTime(t *testing.T) {
	// time.Unix(-60, 0) → Unix second -60 → minute -1 (negative modulo path)
	clock := &fakeClock{t: time.Unix(-60, 0)}
	d := NewStormDetector(50, clock.Now)

	// Record() must not panic when minute is negative.
	for i := 0; i < 3; i++ {
		d.Record()
	}
	if got := d.Count(); got != 3 {
		t.Fatalf("count at minute -1: got %d, want 3", got)
	}

	// Advance into a second negative minute (-2) and record more.
	clock.advance(-60 * time.Second) // minute -2
	for i := 0; i < 2; i++ {
		d.Record()
	}
	if got := d.Count(); got != 5 {
		t.Fatalf("count spanning minutes -2..-1: got %d, want 5", got)
	}

	// Advance past the 5-minute window so minute -2 expires.
	// At minute 3 the cutoff is 3-4 = -1, so minute -2 falls out.
	clock.advance(5 * 60 * time.Second) // forward to minute ~3
	if got := d.Count(); got != 3 {
		t.Fatalf("after minute -2 expires: got %d, want 3 (only minute -1 in window)", got)
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
