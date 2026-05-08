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
