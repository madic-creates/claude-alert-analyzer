package shared

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestServer_Enqueue(t *testing.T) {
	var processed atomic.Int64
	metrics := new(AlertMetrics)

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
	if metrics.AlertsQueued.Load() != 1 {
		t.Errorf("AlertsQueued = %d, want 1", metrics.AlertsQueued.Load())
	}
}

func TestServer_Enqueue_Full(t *testing.T) {
	metrics := new(AlertMetrics)

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
	if metrics.AlertsQueueFull.Load() != 1 {
		t.Errorf("AlertsQueueFull = %d, want 1", metrics.AlertsQueueFull.Load())
	}
}

func TestServer_BuildMux_Health(t *testing.T) {
	metrics := new(AlertMetrics)
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

func TestServer_BuildMux_Metrics(t *testing.T) {
	metrics := new(AlertMetrics)
	metrics.WebhooksReceived.Add(5)

	srv := NewServer(ServerConfig{Port: "0", WorkerCount: 1, QueueSize: 5, DrainTimeout: 5 * time.Second}, metrics,
		func(ctx context.Context, alert AlertPayload) {})

	mux := srv.BuildMux(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET /metrics = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "webhooks_received_total 5") {
		t.Errorf("body missing expected metric, got:\n%s", w.Body.String())
	}
}

func TestServer_SafeProcess_PanicDoesNotPropagate(t *testing.T) {
	// safeProcess must recover panics so the caller (worker goroutine) stays alive.
	metrics := new(AlertMetrics)
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
	// First call panics — safeProcess must not panic itself.
	srv.safeProcess(ctx, AlertPayload{Fingerprint: "panic-me"})
	// Second call must execute normally, proving the panic was recovered.
	srv.safeProcess(ctx, AlertPayload{Fingerprint: "ok"})

	if processed.Load() != 1 {
		t.Errorf("processed = %d after panic, want 1", processed.Load())
	}
}

func TestServer_SafeProcess_PanicLogsStack(t *testing.T) {
	// safeProcess must include the goroutine stack trace in the log so production
	// panics can be diagnosed without a core dump.
	metrics := new(AlertMetrics)

	var loggedStack string
	srv := NewServer(ServerConfig{
		Port: "0", WorkerCount: 1, QueueSize: 5, DrainTimeout: time.Second,
	}, metrics, func(ctx context.Context, alert AlertPayload) {
		panic("stack test panic")
	})

	// Replace the slog default handler with one that captures the "stack" attribute.
	// We intentionally do NOT forward to the old handler: slog.SetDefault bridges
	// log.Default()'s output back through the new slog handler, so forwarding to
	// the old defaultHandler creates a cycle that deadlocks on log.Logger's mutex.
	handler := &stackCaptureHandler{capture: &loggedStack}
	old := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(old)

	srv.safeProcess(context.Background(), AlertPayload{Fingerprint: "stack-test"})

	if loggedStack == "" {
		t.Fatal("safeProcess did not log a stack trace on panic")
	}
	// The stack must mention this test file so it's actionable.
	if !strings.Contains(loggedStack, "server_test.go") {
		t.Errorf("stack trace does not reference server_test.go:\n%s", loggedStack)
	}
}

// stackCaptureHandler is a slog.Handler that captures the "stack" attribute value
// and discards all other output. It must NOT forward to another handler: slog.SetDefault
// bridges log.Default()'s writer back through the active slog handler, so forwarding to
// the old defaultHandler creates a re-entrant cycle that deadlocks on log.Logger's mutex.
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

func TestServer_BuildMux_Ready_NilReadyCheck(t *testing.T) {
	metrics := new(AlertMetrics)
	srv := NewServer(ServerConfig{Port: "0", WorkerCount: 1, QueueSize: 5, DrainTimeout: 5 * time.Second}, metrics,
		func(ctx context.Context, alert AlertPayload) {})
	// ReadyCheck is nil — should always return 200.
	mux := srv.BuildMux(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest("GET", "/ready", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET /ready (nil check) = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "ready") {
		t.Errorf("body = %q, want 'ready'", w.Body.String())
	}
}

func TestServer_BuildMux_Ready_CheckPasses(t *testing.T) {
	metrics := new(AlertMetrics)
	srv := NewServer(ServerConfig{Port: "0", WorkerCount: 1, QueueSize: 5, DrainTimeout: 5 * time.Second}, metrics,
		func(ctx context.Context, alert AlertPayload) {})
	srv.ReadyCheck = func(ctx context.Context) error { return nil }

	mux := srv.BuildMux(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest("GET", "/ready", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET /ready (check passes) = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "ready") {
		t.Errorf("body = %q, want 'ready'", w.Body.String())
	}
}

func TestServer_BuildMux_Ready_CheckFails(t *testing.T) {
	metrics := new(AlertMetrics)
	srv := NewServer(ServerConfig{Port: "0", WorkerCount: 1, QueueSize: 5, DrainTimeout: 5 * time.Second}, metrics,
		func(ctx context.Context, alert AlertPayload) {})
	srv.ReadyCheck = func(ctx context.Context) error { return fmt.Errorf("k8s api unreachable") }

	mux := srv.BuildMux(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest("GET", "/ready", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("GET /ready (check fails) = %d, want 503", w.Code)
	}
	if !strings.Contains(w.Body.String(), "not ready") {
		t.Errorf("body = %q, want 'not ready: ...'", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "k8s api unreachable") {
		t.Errorf("body = %q, want error message included", w.Body.String())
	}
}

func TestServer_BuildMux_WebhookCountsMetric(t *testing.T) {
	metrics := new(AlertMetrics)
	srv := NewServer(ServerConfig{Port: "0", WorkerCount: 1, QueueSize: 5, DrainTimeout: 5 * time.Second}, metrics,
		func(ctx context.Context, alert AlertPayload) {})

	called := false
	mux := srv.BuildMux(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/webhook", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if !called {
		t.Fatal("webhook handler was not called")
	}
	if metrics.WebhooksReceived.Load() != 1 {
		t.Errorf("WebhooksReceived = %d, want 1", metrics.WebhooksReceived.Load())
	}
}
