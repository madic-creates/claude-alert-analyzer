package shared

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
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

// TestCircuitBreaker_ProbeWatchdogIsAuthoritative verifies that once the
// probe-watchdog has fired (inside Acquire), a late Done() call on the same
// probe permit does not override the watchdog's decision. The watchdog
// treats a stuck probe as failed and re-opens the breaker; if a late
// Done(nil) could then close the breaker, the safety mechanism would be
// silently defeated. Late Done(err) must not extend the open period either.
func TestCircuitBreaker_ProbeWatchdogIsAuthoritative(t *testing.T) {
	t.Run("late_success_does_not_close", func(t *testing.T) {
		clk := &fakeClock{t: time.Unix(0, 0)}
		b := NewCircuitBreaker(1, 10*time.Second, 5*time.Second, clk.Now)

		p, _ := b.Acquire()
		p.Done(errors.New("fail"))
		clk.advance(11 * time.Second)
		probe, _ := b.Acquire()
		if !probe.IsProbe() {
			t.Fatal("expected probe permit")
		}

		// Advance past maxProbeDuration and call Acquire to fire the watchdog.
		clk.advance(6 * time.Second)
		if _, err := b.Acquire(); !errors.Is(err, ErrCircuitOpen) {
			t.Fatalf("watchdog Acquire: err=%v, want ErrCircuitOpen", err)
		}

		// The slow probe eventually succeeds. The watchdog already decided.
		probe.Done(nil)

		// Within openDuration the breaker must remain open.
		if _, err := b.Acquire(); !errors.Is(err, ErrCircuitOpen) {
			t.Fatalf("after late probe success: err=%v, want ErrCircuitOpen", err)
		}
	})

	t.Run("late_failure_does_not_extend_open", func(t *testing.T) {
		clk := &fakeClock{t: time.Unix(0, 0)}
		b := NewCircuitBreaker(1, 10*time.Second, 5*time.Second, clk.Now)

		p, _ := b.Acquire()
		p.Done(errors.New("fail"))
		clk.advance(11 * time.Second)
		probe, _ := b.Acquire()

		// Fire the watchdog at t=17s, openedAt becomes 17s.
		clk.advance(6 * time.Second)
		if _, err := b.Acquire(); !errors.Is(err, ErrCircuitOpen) {
			t.Fatalf("watchdog Acquire: err=%v, want ErrCircuitOpen", err)
		}

		// At t=22s, before the open period (17s + 10s = 27s) has elapsed,
		// the slow probe finally returns an error.
		clk.advance(5 * time.Second)
		probe.Done(errors.New("probe failed late"))

		// At t=28s (11s after watchdog), the open period from the watchdog
		// has elapsed: Acquire must issue a fresh probe. If the late Done(err)
		// had overwritten openedAt to 22s, the breaker would still be open
		// until 32s.
		clk.advance(6 * time.Second)
		next, err := b.Acquire()
		if err != nil {
			t.Fatalf("post-open-period Acquire: err=%v, want fresh probe", err)
		}
		if !next.IsProbe() {
			t.Fatal("expected fresh probe permit after open period elapsed")
		}
	})
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

// TestCircuitBreaker_State_ExpiredProbeReportsOpen verifies that State()
// returns 1 (open) when the half-open probe has exceeded maxProbeDuration
// but Acquire() has not yet been called to apply the watchdog transition.
// Without this check, the claude_circuit_breaker_state gauge can report
// 2 (half-open) during quiet periods after a probe times out, misleading
// operators who rely on the gauge to understand circuit-breaker health.
func TestCircuitBreaker_State_ExpiredProbeReportsOpen(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	b := NewCircuitBreaker(1, 10*time.Second, 5*time.Second, clk.Now)

	// Trip the breaker.
	p, _ := b.Acquire()
	p.Done(errors.New("fail"))

	// Advance past openDuration so a probe is issued.
	clk.advance(11 * time.Second)
	probe, err := b.Acquire()
	if err != nil || !probe.IsProbe() {
		t.Fatalf("expected probe permit: err=%v isProbe=%v", err, probe.IsProbe())
	}
	// Probe is in-flight but never settled — simulates a stuck/slow analysis.

	// Within maxProbeDuration State() should report half-open (2).
	clk.advance(4 * time.Second)
	if got := b.State(); got != 2 {
		t.Fatalf("State during probe window = %d, want 2 (half-open)", got)
	}

	// Past maxProbeDuration (5s): the probe has effectively expired.
	// State() must report open (1) without requiring an Acquire() call to
	// apply the watchdog transition first.
	clk.advance(2 * time.Second) // total probe age = 6s > 5s maxProbeDuration
	if got := b.State(); got != 1 {
		t.Fatalf("State after probe expiry = %d, want 1 (open)", got)
	}
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

// TestCircuitBreaker_NonPositiveDurationLogsWarn verifies that the
// non-positive duration fallback in NewCircuitBreaker emits a slog.Warn
// record naming the offending parameter. Production callers enforce a
// positive bound via ParseIntEnv, so the warn surfaces misuse by direct
// callers (tests or future code paths) rather than catching real
// misconfiguration — the value is observable instead of silent.
func TestCircuitBreaker_NonPositiveDurationLogsWarn(t *testing.T) {
	cases := []struct {
		name      string
		open      time.Duration
		probe     time.Duration
		wantParam string
	}{
		{"open_zero", 0, time.Minute, "openDuration"},
		{"open_negative", -time.Second, time.Minute, "openDuration"},
		{"probe_zero", time.Minute, 0, "maxProbeDuration"},
		{"probe_negative", time.Minute, -time.Second, "maxProbeDuration"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
			old := slog.Default()
			slog.SetDefault(slog.New(handler))
			t.Cleanup(func() { slog.SetDefault(old) })

			b := NewCircuitBreaker(1, tc.open, tc.probe, time.Now)
			if b == nil {
				t.Fatal("expected non-nil breaker")
			}

			found := false
			for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
				if line == "" {
					continue
				}
				var rec map[string]any
				if json.Unmarshal([]byte(line), &rec) != nil {
					continue
				}
				if rec["msg"] != "circuit breaker: non-positive duration substituted with default" {
					continue
				}
				if rec["param"] != tc.wantParam {
					continue
				}
				found = true
				if _, ok := rec["value"]; !ok {
					t.Errorf("slog record missing value field; record: %s", line)
				}
				if _, ok := rec["default"]; !ok {
					t.Errorf("slog record missing default field; record: %s", line)
				}
			}
			if !found {
				t.Errorf("no slog warn record with param=%q found; log output:\n%s", tc.wantParam, buf.String())
			}
		})
	}
}

// TestCircuitBreaker_ProbeWatchdogLogsWarn verifies that when the
// probe-watchdog fires inside Acquire (stuck in-flight probe past
// maxProbeDuration), a slog.Warn is emitted naming the param and the
// elapsed duration so operators have a diagnostic signal for the gauge
// flip back to open. Parallel to the non-positive duration warn emitted
// by NewCircuitBreaker.
func TestCircuitBreaker_ProbeWatchdogLogsWarn(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	old := slog.Default()
	slog.SetDefault(slog.New(handler))
	t.Cleanup(func() { slog.SetDefault(old) })

	clk := &fakeClock{t: time.Unix(0, 0)}
	b := NewCircuitBreaker(1, 10*time.Second, 5*time.Second, clk.Now)

	p, _ := b.Acquire()
	p.Done(errors.New("fail"))
	clk.advance(11 * time.Second)
	probe, _ := b.Acquire()
	if !probe.IsProbe() {
		t.Fatal("expected probe permit")
	}

	// Advance past maxProbeDuration and call Acquire to fire the watchdog.
	clk.advance(6 * time.Second)
	if _, err := b.Acquire(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("watchdog Acquire: err=%v, want ErrCircuitOpen", err)
	}

	found := false
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if rec["msg"] != "circuit breaker: probe watchdog re-opened breaker after stuck probe" {
			continue
		}
		found = true
		if _, ok := rec["maxProbeDuration"]; !ok {
			t.Errorf("slog record missing maxProbeDuration field; record: %s", line)
		}
		if _, ok := rec["elapsed"]; !ok {
			t.Errorf("slog record missing elapsed field; record: %s", line)
		}
	}
	if !found {
		t.Errorf("no probe-watchdog slog warn found; log output:\n%s", buf.String())
	}
}

// TestCircuitBreaker_LateProbeDropLogsDebug verifies that when a slow probe's
// Done() is called after the probe-watchdog has already fired and re-opened the
// breaker, a slog.Debug is emitted with the probe outcome (probeErr) and how
// long after the watchdog the late result arrived (lateBy). This lets operators
// diagnose whether the analysis pipeline is slow-but-healthy (probeErr=nil) or
// genuinely broken (probeErr=non-nil) when the watchdog fires.
func TestCircuitBreaker_LateProbeDropLogsDebug(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	old := slog.Default()
	slog.SetDefault(slog.New(handler))
	t.Cleanup(func() { slog.SetDefault(old) })

	clk := &fakeClock{t: time.Unix(0, 0)}
	b := NewCircuitBreaker(1, 10*time.Second, 5*time.Second, clk.Now)

	// Open the breaker.
	p, _ := b.Acquire()
	p.Done(errors.New("fail"))
	clk.advance(11 * time.Second)

	// Obtain a probe permit.
	probe, _ := b.Acquire()
	if !probe.IsProbe() {
		t.Fatal("expected probe permit")
	}

	// Fire the watchdog by advancing past maxProbeDuration and calling Acquire.
	clk.advance(6 * time.Second)
	if _, err := b.Acquire(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("watchdog Acquire: err=%v, want ErrCircuitOpen", err)
	}

	// The slow probe finally returns nil (success) after the watchdog fired.
	probe.Done(nil)

	found := false
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if rec["msg"] != "circuit breaker: dropping late probe result after watchdog re-opened" {
			continue
		}
		found = true
		if _, ok := rec["probeErr"]; !ok {
			t.Errorf("slog record missing probeErr field; record: %s", line)
		}
		if _, ok := rec["lateBy"]; !ok {
			t.Errorf("slog record missing lateBy field; record: %s", line)
		}
	}
	if !found {
		t.Errorf("no late-probe-drop slog debug found; log output:\n%s", buf.String())
	}
}

// TestCircuitBreaker_ThresholdOpenLogsWarn verifies that when consecutive
// failures reach the threshold and the breaker opens, a slog.Warn is emitted
// naming the threshold and failure count. Parallel to the probe-watchdog warn
// emitted by Acquire: operators see both kinds of open transition in logs, not
// just the gauge flip in metrics.
func TestCircuitBreaker_ThresholdOpenLogsWarn(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	old := slog.Default()
	slog.SetDefault(slog.New(handler))
	t.Cleanup(func() { slog.SetDefault(old) })

	clk := &fakeClock{t: time.Unix(0, 0)}
	b := NewCircuitBreaker(2, time.Minute, time.Minute, clk.Now)

	// First failure: below threshold, no warn expected.
	p, _ := b.Acquire()
	p.Done(errors.New("fail 1"))
	if strings.Contains(buf.String(), "opened after consecutive failures") {
		t.Fatal("expected no warn before threshold is reached")
	}

	// Second failure: reaches threshold=2, warn must fire.
	p, _ = b.Acquire()
	p.Done(errors.New("fail 2"))

	found := false
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if rec["msg"] != "circuit breaker: opened after consecutive failures" {
			continue
		}
		found = true
		if got := rec["threshold"]; got != float64(2) {
			t.Errorf("threshold = %v, want 2", got)
		}
		if got := rec["consecFailures"]; got != float64(2) {
			t.Errorf("consecFailures = %v, want 2", got)
		}
	}
	if !found {
		t.Errorf("no threshold-open slog warn found; log output:\n%s", buf.String())
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

// TestCircuitBreaker_ProbeWatchdogFiresAtExactBoundary verifies the exact
// boundary of the probe-watchdog guard: when the elapsed probe time equals
// maxProbeDuration exactly, the watchdog must fire. Both Acquire() and State()
// use `>= maxProbeDuration`, so elapsed == maxProbeDuration is the critical
// in-bounds case. A mutation of >= to > would leave the probe in-flight at the
// boundary; the existing tests only check at 4s (below, half-open) and 6s
// (above, open) for maxProbeDuration=5s, so neither catches the mutation.
func TestCircuitBreaker_ProbeWatchdogFiresAtExactBoundary(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	const maxProbeDuration = 5 * time.Second
	b := NewCircuitBreaker(1, 10*time.Second, maxProbeDuration, clk.Now)

	// Trip the breaker.
	p, _ := b.Acquire()
	p.Done(errors.New("fail"))

	// Advance past openDuration so a probe is issued. probeStartedAt = t=11s.
	clk.advance(11 * time.Second)
	probe, err := b.Acquire()
	if err != nil || !probe.IsProbe() {
		t.Fatalf("expected probe permit: err=%v isProbe=%v", err, probe.IsProbe())
	}

	// Advance exactly maxProbeDuration so elapsed == maxProbeDuration.
	clk.advance(maxProbeDuration)

	// State() must report open (1) at the boundary without Acquire() having fired.
	if got := b.State(); got != 1 {
		t.Fatalf("State() at elapsed==maxProbeDuration: got %d, want 1 (open)", got)
	}

	// Acquire() must fire the watchdog and return ErrCircuitOpen.
	if _, err := b.Acquire(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("Acquire() at elapsed==maxProbeDuration: got err=%v, want ErrCircuitOpen", err)
	}
}

// TestCircuitBreaker_OpenTransitionsAtExactDuration verifies the exact boundary
// of the open-duration guard in Acquire(): when elapsed == openDuration exactly,
// the condition `now.Sub(b.openedAt) < b.openDuration` is false and the breaker
// transitions to half-open, issuing a probe permit. A < → <= mutation would keep
// the breaker open at the boundary. The existing TestCircuitBreaker_OpenToHalfOpenAfterDuration
// checks at 29s (below) and 31s (above) for openDuration=30s but never at exactly 30s,
// so the mutation goes undetected without this test.
func TestCircuitBreaker_OpenTransitionsAtExactDuration(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	const openDuration = 30 * time.Second
	b := NewCircuitBreaker(1, openDuration, time.Minute, clk.Now)

	// Trip the breaker at t=0; openedAt=0.
	p, _ := b.Acquire()
	p.Done(errors.New("fail"))

	// One nanosecond before the boundary: must remain open.
	clk.advance(openDuration - time.Nanosecond)
	if _, err := b.Acquire(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("1ns before boundary: err=%v, want ErrCircuitOpen", err)
	}

	// Exactly at the boundary: elapsed == openDuration, `< openDuration` is false.
	// Must transition to half-open and issue a probe permit.
	clk.advance(time.Nanosecond)
	probe, err := b.Acquire()
	if err != nil {
		t.Fatalf("at elapsed==openDuration: got err=%v, want probe permit", err)
	}
	if !probe.IsProbe() {
		t.Fatal("at elapsed==openDuration: expected probe permit (< guard, not <=)")
	}
}

// TestCircuitBreaker_Acquire_InvalidState covers the default branch in
// Acquire()'s switch statement. breakerState is a private iota type with
// exactly three valid values; the default case is a safety guard against
// memory corruption or future refactors introducing an unhandled state.
// We reach it by forcibly writing an out-of-range value, which documents
// the invariant and prevents coverage gaps from masking real regressions.
func TestCircuitBreaker_Acquire_InvalidState(t *testing.T) {
	b := NewCircuitBreaker(3, time.Minute, time.Minute, time.Now)
	b.mu.Lock()
	b.state = breakerState(99) // invalid — not closed/open/half-open
	b.mu.Unlock()
	_, err := b.Acquire()
	if !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("invalid state: expected ErrCircuitOpen, got: %v", err)
	}
}
