package shared

import (
	"context"
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
