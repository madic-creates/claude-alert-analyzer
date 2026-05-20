package shared

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestServer_Enqueue(t *testing.T) {
	var processed atomic.Int64
	metrics := NewAlertMetrics(nil)

	srv := NewServer(ServerConfig{
		Port:         "0",
		WorkerCount:  1,
		QueueSize:    5,
		DrainTimeout: 5 * time.Second,
	}, metrics, func(ctx context.Context, alert AlertPayload) {
		processed.Add(1)
	})

	if !srv.Enqueue(AlertPayload{Fingerprint: "a"}) {
		t.Fatal("enqueue should succeed")
	}
}

func TestServer_Enqueue_Full(t *testing.T) {
	metrics := NewAlertMetrics(nil)

	srv := NewServer(ServerConfig{
		Port:         "0",
		WorkerCount:  0,
		QueueSize:    1,
		DrainTimeout: 5 * time.Second,
	}, metrics, func(ctx context.Context, alert AlertPayload) {})

	srv.Enqueue(AlertPayload{Fingerprint: "a"})
	if srv.Enqueue(AlertPayload{Fingerprint: "b"}) {
		t.Fatal("second enqueue should fail when queue is full")
	}
}

func TestServer_BuildMux_Health(t *testing.T) {
	metrics := NewAlertMetrics(nil)
	srv := NewServer(ServerConfig{Port: "0", WorkerCount: 1, QueueSize: 5, DrainTimeout: 5 * time.Second}, metrics,
		func(ctx context.Context, alert AlertPayload) {})

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux := srv.BuildMux(dummyHandler)
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET /health = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "ok") {
		t.Errorf("body = %q, want 'ok'", w.Body.String())
	}
}

func TestServer_BuildMux_Metrics_NotOnMainMux(t *testing.T) {
	metrics := NewAlertMetrics(nil)
	srv := NewServer(ServerConfig{Port: "0", WorkerCount: 1, QueueSize: 5, DrainTimeout: 5 * time.Second}, metrics,
		func(ctx context.Context, alert AlertPayload) {})

	mux := srv.BuildMux(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Errorf("GET /metrics on main mux should not return 200 (got %d); metrics must be on the metrics mux only", w.Code)
	}
}

// TestServer_BuildMetricsMux_NilProm verifies the zero-value Prom path returns
// a stable 200 with empty body — the path tests rely on when constructing
// AlertMetrics with NewAlertMetrics(nil).
func TestServer_BuildMetricsMux_NilProm(t *testing.T) {
	metrics := NewAlertMetrics(nil)
	srv := NewServer(ServerConfig{Port: "0", WorkerCount: 1, QueueSize: 5, DrainTimeout: 5 * time.Second}, metrics,
		func(ctx context.Context, alert AlertPayload) {})
	mux := srv.BuildMetricsMux()
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", w.Header().Get("Content-Type"))
	}
}

// TestServer_BuildMetricsMux_RealProm verifies the real-Prom path serves
// recorded metrics via promhttp.
func TestServer_BuildMetricsMux_RealProm(t *testing.T) {
	prom := NewPrometheusMetricsForTest(ProductK8s)
	metrics := NewAlertMetrics(prom)
	metrics.RecordWebhookOutcome(WebhookAccepted)
	srv := NewServer(ServerConfig{Port: "0", WorkerCount: 1, QueueSize: 5, DrainTimeout: 5 * time.Second}, metrics,
		func(ctx context.Context, alert AlertPayload) {})
	mux := srv.BuildMetricsMux()
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "alert_analyzer_webhooks_total") {
		t.Errorf("body missing expected metric name; head: %s", w.Body.String()[:min(500, w.Body.Len())])
	}
}

func TestServer_SafeProcess_PanicDoesNotPropagate(t *testing.T) {
	metrics := NewAlertMetrics(nil)
	var processed atomic.Int64
	callCount := atomic.Int64{}

	srv := NewServer(ServerConfig{
		Port: "0", WorkerCount: 1, QueueSize: 5, DrainTimeout: time.Second,
	}, metrics, func(ctx context.Context, alert AlertPayload) {
		if callCount.Add(1) == 1 {
			panic("deliberate test panic")
		}
		processed.Add(1)
	})

	ctx := context.Background()
	srv.safeProcess(ctx, AlertPayload{Fingerprint: "panic-me"})
	srv.safeProcess(ctx, AlertPayload{Fingerprint: "ok"})

	if processed.Load() != 1 {
		t.Errorf("processed = %d after panic, want 1", processed.Load())
	}
}

func TestServer_SafeProcess_PanicLogsStack(t *testing.T) {
	metrics := NewAlertMetrics(nil)

	var loggedStack string
	srv := NewServer(ServerConfig{
		Port: "0", WorkerCount: 1, QueueSize: 5, DrainTimeout: time.Second,
	}, metrics, func(ctx context.Context, alert AlertPayload) {
		panic("stack test panic")
	})

	handler := &stackCaptureHandler{capture: &loggedStack}
	old := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(old)

	srv.safeProcess(context.Background(), AlertPayload{Fingerprint: "stack-test"})

	if loggedStack == "" {
		t.Fatal("safeProcess did not log a stack trace on panic")
	}
	if !strings.Contains(loggedStack, "server_test.go") {
		t.Errorf("stack trace does not reference server_test.go:\n%s", loggedStack)
	}
}

type stackCaptureHandler struct {
	capture *string
}

func (h *stackCaptureHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *stackCaptureHandler) Handle(_ context.Context, r slog.Record) error {
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "stack" {
			*h.capture = a.Value.String()
		}
		return true
	})
	return nil
}

func (h *stackCaptureHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *stackCaptureHandler) WithGroup(_ string) slog.Handler      { return h }

// TestServer_Run_DrainTimerBiasTowardDone verifies the bias guard in Run():
// when workers finish at the same instant the drain timer fires, the outer
// select may pick the timer branch — but the inner non-blocking re-check on
// done must still pick done and avoid emitting the misleading "worker drain
// timeout, cancelling" log line. We force the drain-timer branch to be
// selected deterministically by blocking the worker until the test hook
// fires; the hook then releases the worker and waits long enough for the
// done channel to close before returning.
func TestServer_Run_DrainTimerBiasTowardDone(t *testing.T) {
	release := make(chan struct{})
	var processed atomic.Int64
	metrics := NewAlertMetrics(nil)

	srv := NewServer(ServerConfig{
		Port:         "0",
		MetricsPort:  "0",
		WorkerCount:  1,
		QueueSize:    5,
		DrainTimeout: 5 * time.Millisecond,
	}, metrics, func(ctx context.Context, alert AlertPayload) {
		<-release
		processed.Add(1)
	})

	var warnSeen atomic.Bool
	old := slog.Default()
	slog.SetDefault(slog.New(&warnSubstringCaptureHandler{
		seen:      &warnSeen,
		substring: "worker drain timeout",
	}))
	defer slog.SetDefault(old)

	var hookFired atomic.Bool
	testHookBeforeServerDrainRecheck = func() {
		hookFired.Store(true)
		// Release the blocked worker so it can complete cleanly. After the
		// worker returns from safeProcess, the goroutine exits the range
		// over the now-closed queue and signals wg.Done(); the trampoline
		// goroutine then closes done. Poll until processed reaches 1, then
		// give the trampoline a brief window to close done before we
		// return into the inner re-check.
		close(release)
		deadline := time.Now().Add(500 * time.Millisecond)
		for time.Now().Before(deadline) {
			if processed.Load() == 1 {
				break
			}
			time.Sleep(time.Millisecond)
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer func() { testHookBeforeServerDrainRecheck = nil }()

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		srv.Run(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	}()

	time.Sleep(50 * time.Millisecond)

	srv.Enqueue(AlertPayload{Fingerprint: "drain-bias-test"})

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}

	select {
	case <-runDone:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return within 10 seconds of SIGTERM")
	}

	if !hookFired.Load() {
		t.Fatal("test hook never fired — drain-timer branch was not exercised; test does not cover the race")
	}
	if processed.Load() != 1 {
		t.Errorf("processed = %d, want 1 (worker should have finished cleanly)", processed.Load())
	}
	if warnSeen.Load() {
		t.Error("misleading 'worker drain timeout' warn log emitted despite workers completing in time — bias re-check did not pick done")
	}
}

type warnSubstringCaptureHandler struct {
	seen      *atomic.Bool
	substring string
}

func (h *warnSubstringCaptureHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *warnSubstringCaptureHandler) Handle(_ context.Context, r slog.Record) error {
	if r.Level >= slog.LevelWarn && strings.Contains(r.Message, h.substring) {
		h.seen.Store(true)
	}
	return nil
}

func (h *warnSubstringCaptureHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *warnSubstringCaptureHandler) WithGroup(_ string) slog.Handler      { return h }

func TestServer_Run_GracefulShutdown(t *testing.T) {
	var processed atomic.Int64
	metrics := NewAlertMetrics(nil)

	srv := NewServer(ServerConfig{
		Port:         "0",
		MetricsPort:  "0",
		WorkerCount:  1,
		QueueSize:    5,
		DrainTimeout: 3 * time.Second,
	}, metrics, func(ctx context.Context, alert AlertPayload) {
		processed.Add(1)
	})

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		srv.Run(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	}()

	time.Sleep(50 * time.Millisecond)

	srv.Enqueue(AlertPayload{Fingerprint: "run-drain-fp"})

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}

	select {
	case <-runDone:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return within 10 seconds of SIGTERM")
	}

	if processed.Load() != 1 {
		t.Errorf("processed = %d after graceful shutdown, want 1", processed.Load())
	}
}
