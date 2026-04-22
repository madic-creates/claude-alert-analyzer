package shared

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// TestRunToolLoop_RoundParseError verifies that when the Claude API returns a
// 200 OK with a non-JSON body during a mid-conversation tool round (e.g. a CDN
// maintenance page or a truncated response), RunToolLoop propagates a clear
// "round N parse:" error rather than panicking or silently returning empty
// output. This covers line 177 (the round parse error path) which was
// previously untested — the analogous path in Analyze is covered by
// TestAnalyze_ParseResponseError but RunToolLoop had no equivalent.
func TestRunToolLoop_RoundParseError(t *testing.T) {
	var callCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")

		if call == 1 {
			// Round 1: return a valid tool call so the loop advances to round 2.
			fmt.Fprint(w, `{
				"content": [
					{"type": "tool_use", "id": "toolu_1", "name": "execute_command", "input": {"command": ["uptime"]}}
				],
				"stop_reason": "tool_use",
				"usage": {"input_tokens": 20, "output_tokens": 10}
			}`)
		} else {
			// Round 2: simulate a CDN maintenance page — 200 OK but non-JSON.
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<!DOCTYPE html><html><body>Maintenance</body></html>`)
		}
	}))
	defer srv.Close()

	client := &ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "test-key", Model: "test"}
	tools := []Tool{{Name: "execute_command", Description: "test", InputSchema: InputSchema{Type: "object"}}}

	_, err := client.RunToolLoop(
		// context.Background is fine — the request will complete, just with bad JSON
		t.Context(),
		"system", "user prompt", tools, 10,
		func(name string, input json.RawMessage) (string, error) { return "load: 0.1", nil },
	)

	if err == nil {
		t.Fatal("expected error when tool round returns non-JSON body, got nil")
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Errorf("error should mention 'parse', got: %v", err)
	}
}

// TestRunToolLoop_SummaryParseError verifies that when the forced-summary
// request (sent after maxRounds is exhausted) returns a 200 OK with a
// non-JSON body, RunToolLoop returns a "summary parse:" error rather than
// panicking or silently producing empty output. This covers lines 267-269
// (the summary JSON unmarshal error path), which is the summary-turn analogue
// of the per-round parse error tested above.
func TestRunToolLoop_SummaryParseError(t *testing.T) {
	var callCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")

		if call == 1 {
			// Only round (maxRounds=1): request a tool call to exhaust the budget.
			fmt.Fprint(w, `{
				"content": [
					{"type": "tool_use", "id": "toolu_1", "name": "execute_command", "input": {"command": ["df", "-h"]}}
				],
				"stop_reason": "tool_use",
				"usage": {"input_tokens": 30, "output_tokens": 10}
			}`)
		} else {
			// Forced-summary call: simulate a non-JSON 200 OK.
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "unexpected plain-text response from proxy")
		}
	}))
	defer srv.Close()

	client := &ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "test-key", Model: "test"}
	tools := []Tool{{Name: "execute_command", Description: "test", InputSchema: InputSchema{Type: "object"}}}

	_, err := client.RunToolLoop(
		t.Context(),
		"system", "user prompt", tools, 1,
		func(name string, input json.RawMessage) (string, error) { return "ok", nil },
	)

	if err == nil {
		t.Fatal("expected error when summary round returns non-JSON body, got nil")
	}
	if !strings.Contains(err.Error(), "summary") {
		t.Errorf("error should mention 'summary', got: %v", err)
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Errorf("error should mention 'parse', got: %v", err)
	}
}

// TestRunToolLoop_ForcedSummaryEmptyContent verifies that when the forced-summary
// turn returns a 200 OK with an empty content array (e.g. Claude returned no text
// blocks), RunToolLoop returns ("", nil) rather than an error. The empty result
// is then caught by the pipeline's empty-analysis guard which fires a failure
// notification. This covers lines 286-288 (the slog.Warn path for an empty
// forced-summary analysis) which was previously untested.
func TestRunToolLoop_ForcedSummaryEmptyContent(t *testing.T) {
	var callCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")

		if call == 1 {
			// Only round (maxRounds=1): exhaust the budget with a tool call.
			fmt.Fprint(w, `{
				"content": [
					{"type": "tool_use", "id": "toolu_1", "name": "execute_command", "input": {"command": ["uptime"]}}
				],
				"stop_reason": "tool_use",
				"usage": {"input_tokens": 20, "output_tokens": 10}
			}`)
		} else {
			// Forced-summary call: return an empty content array (no text blocks).
			fmt.Fprint(w, `{
				"content": [],
				"stop_reason": "end_turn",
				"usage": {"input_tokens": 100, "output_tokens": 0}
			}`)
		}
	}))
	defer srv.Close()

	client := &ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "test-key", Model: "test"}
	tools := []Tool{{Name: "execute_command", Description: "test", InputSchema: InputSchema{Type: "object"}}}

	result, err := client.RunToolLoop(
		t.Context(),
		"system", "user prompt", tools, 1,
		func(name string, input json.RawMessage) (string, error) { return "load: 0.1", nil },
	)

	if err != nil {
		t.Fatalf("expected nil error for empty forced-summary content, got: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty result for empty forced-summary content, got: %q", result)
	}
}

// TestSendRequest_CreateRequestError verifies that sendRequest returns a "create
// request: ..." error when http.NewRequestWithContext fails due to an invalid
// BaseURL (e.g. a null byte injected by a misconfigured environment variable).
// This covers lines 68-70 of claude.go, which were previously untested because
// all existing tests use valid http/https URLs constructed by httptest.NewServer.
func TestSendRequest_CreateRequestError(t *testing.T) {
	// A null byte in the URL makes http.NewRequestWithContext fail with
	// "invalid URL" before any network I/O takes place.
	client := &ClaudeClient{
		HTTP:    http.DefaultClient,
		BaseURL: "http://host\x00invalid/v1/messages",
		APIKey:  "test-key",
		Model:   "test",
	}
	_, err := client.sendRequest(context.Background(), map[string]string{"k": "v"})
	if err == nil {
		t.Fatal("expected error for invalid URL, got nil")
	}
	if !strings.Contains(err.Error(), "create request") {
		t.Errorf("error should mention 'create request', got: %v", err)
	}
}

// TestSendRequest_ReadBodyError verifies that sendRequest returns a "read response: ..."
// error (and increments the errorCounter) when the server sends a valid HTTP 200
// header but then drops the TCP connection before delivering the full body. This is
// a real production failure mode (e.g. a load-balancer reset mid-stream) and covers
// the previously-untested io.ReadAll error path in sendRequest (claude.go lines ~91-97).
func TestSendRequest_ReadBodyError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hijack the connection so we can write raw bytes and then close it
		// before the response body is complete, causing the client's io.ReadAll
		// to receive an unexpected EOF.
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("server does not support hijacking")
			http.Error(w, "no hijack", 500)
			return
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			t.Errorf("hijack failed: %v", err)
			return
		}
		// Write a valid HTTP 200 response with Content-Length larger than what
		// we actually send, then close the connection. The client will read the
		// headers successfully (200 OK) and then fail on io.ReadAll because the
		// connection is closed before the promised bytes arrive.
		_, _ = bufrw.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 10000\r\n\r\n{")
		_ = bufrw.Flush()
		_ = conn.Close()
	}))
	defer srv.Close()

	m := &AlertMetrics{Prom: NewPrometheusMetrics()}
	client := &ClaudeClient{
		HTTP:    srv.Client(),
		BaseURL: srv.URL,
		APIKey:  "test-key",
		Model:   "test",
	}
	client.WithPrometheusMetrics(m, "k8s")

	_, err := client.sendRequest(context.Background(), map[string]string{"k": "v"})
	if err == nil {
		t.Fatal("expected error when server drops connection mid-response, got nil")
	}
	if !strings.Contains(err.Error(), "read response") {
		t.Errorf("error should mention 'read response', got: %v", err)
	}

	// Verify that the error counter was incremented via the Prometheus output.
	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	m.MetricsHandler()(rr, req)
	body := rr.Body.String()
	if !strings.Contains(body, `claude_api_errors_total{source="k8s"} 1`) {
		t.Errorf("expected claude_api_errors_total{source=\"k8s\"} 1 in metrics output, got:\n%s", body)
	}
}

// TestNtfyPublisher_Publish_CreateRequestError verifies that Publish returns a
// "create request: ..." error when http.NewRequestWithContext fails because the
// publisher's URL contains an invalid character (null byte). This covers the
// previously-untested branch at ntfy.go lines 85-87, which is the equivalent
// misconfiguration guard for the ntfy pipeline.
func TestNtfyPublisher_Publish_CreateRequestError(t *testing.T) {
	p := &NtfyPublisher{
		HTTP:  http.DefaultClient,
		URL:   "http://host\x00invalid",
		Topic: "alerts",
	}
	err := p.Publish(context.Background(), "title", "default", "body")
	if err == nil {
		t.Fatal("expected error for invalid URL, got nil")
	}
	if !strings.Contains(err.Error(), "create request") {
		t.Errorf("error should mention 'create request', got: %v", err)
	}
}

// TestServer_Enqueue_WhenStopped verifies that Enqueue returns false and does
// not increment AlertsQueued when the server has entered its stopped state
// (i.e. after graceful shutdown has begun and the queue has been closed).
// Without this guard, a caller racing with shutdown would panic with "send on
// closed channel". This covers the previously-untested `if s.stopped` branch
// in Enqueue (server.go) which is the sole protection against that panic.
func TestServer_Enqueue_WhenStopped(t *testing.T) {
	metrics := new(AlertMetrics)
	srv := NewServer(ServerConfig{
		Port:         "0",
		WorkerCount:  1,
		QueueSize:    5,
		DrainTimeout: time.Second,
	}, metrics, func(ctx context.Context, alert AlertPayload) {})

	// Directly set stopped to simulate the post-shutdown state reached inside
	// Run. Because server_test.go is in package shared (same package), we can
	// access the unexported field directly — no production API is needed.
	srv.mu.Lock()
	srv.stopped = true
	srv.mu.Unlock()

	if srv.Enqueue(AlertPayload{Fingerprint: "after-shutdown"}) {
		t.Fatal("Enqueue should return false when server is stopped")
	}
	if metrics.AlertsQueued.Load() != 0 {
		t.Errorf("AlertsQueued = %d, want 0 (must not increment when stopped)", metrics.AlertsQueued.Load())
	}
}

// TestServer_Run_DrainTimeout verifies that when workers do not finish within
// DrainTimeout, Run cancels the worker context and waits for them to stop
// before returning. This exercises the `case <-drainTimer.C` branch in Run
// (server.go) which was previously untested. Without this path, a hung worker
// would prevent graceful shutdown from completing indefinitely.
func TestServer_Run_DrainTimeout(t *testing.T) {
	var contextCancelled atomic.Bool
	metrics := new(AlertMetrics)

	srv := NewServer(ServerConfig{
		Port:         "0",
		MetricsPort:  "0",
		WorkerCount:  1,
		QueueSize:    5,
		DrainTimeout: 150 * time.Millisecond,
	}, metrics, func(ctx context.Context, alert AlertPayload) {
		// Block until the worker context is cancelled by the drain timer.
		<-ctx.Done()
		contextCancelled.Store(true)
	})

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		srv.Run(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	}()

	// Wait for Run to reach <-ctx.Done() (the signal-notify context).
	time.Sleep(50 * time.Millisecond)

	// Enqueue an alert so the worker starts blocking before shutdown is triggered.
	srv.Enqueue(AlertPayload{Fingerprint: "slow-worker"})
	// Let the worker goroutine pick up the alert and enter the blocking process func.
	time.Sleep(50 * time.Millisecond)

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}

	select {
	case <-runDone:
		// Run returned — drain timeout fired, context was cancelled, workers stopped.
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return within 10 seconds after drain timeout")
	}

	if !contextCancelled.Load() {
		t.Error("worker context was not cancelled during drain timeout")
	}
}

// TestServer_Run_ShutdownError verifies that when the HTTP server shutdown
// context expires before all active connections drain, Run logs
// "HTTP server shutdown error" via slog.Error and still returns cleanly.
// This covers the previously-untested slog.Error branches inside the two
// concurrent server.Shutdown goroutines in Run (server.go).
func TestServer_Run_ShutdownError(t *testing.T) {
	// Capture slog.Error calls so we can assert the shutdown error was logged.
	var captured []string
	var capMu sync.Mutex
	capHandler := &shutdownErrCapture{mu: &capMu, msgs: &captured}
	old := slog.Default()
	slog.SetDefault(slog.New(capHandler))
	defer slog.SetDefault(old)

	// Grab a free local port. There is a small TOCTOU window, but it is
	// acceptable in tests: the OS does not immediately reuse recently-freed ports.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("could not bind test port: %v", err)
	}
	port := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	_ = l.Close()

	// unblock keeps the webhook handler alive so the connection stays active
	// during server shutdown, forcing the 5ms ShutdownTimeout to expire.
	unblock := make(chan struct{})
	defer close(unblock) // clean up the handler goroutine after the test

	srv := NewServer(ServerConfig{
		Port:            port,
		MetricsPort:     "0",
		WorkerCount:     1,
		QueueSize:       5,
		DrainTimeout:    time.Second,
		ShutdownTimeout: 5 * time.Millisecond, // expire instantly to force shutdown error
	}, new(AlertMetrics), func(ctx context.Context, alert AlertPayload) {})

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		srv.Run(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Block until signalled so the connection stays active during shutdown.
			<-unblock
			w.WriteHeader(http.StatusOK)
		}))
	}()

	// Wait for the server to be ready to accept connections.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err2 := http.Get("http://127.0.0.1:" + port + "/health")
		if err2 == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Make a POST that will hold the connection open inside the blocking handler.
	go func() {
		req, _ := http.NewRequestWithContext(context.Background(), "POST",
			"http://127.0.0.1:"+port+"/webhook", strings.NewReader("{}"))
		http.DefaultClient.Do(req) //nolint:errcheck
	}()
	// Allow the request to reach the handler before triggering shutdown.
	time.Sleep(30 * time.Millisecond)

	// Trigger graceful shutdown. With ShutdownTimeout=5ms and an active
	// connection, server.Shutdown() will return context.DeadlineExceeded and
	// slog.Error("HTTP server shutdown error") will be logged.
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}

	select {
	case <-runDone:
		// Run returned — shutdown completed despite the active connection.
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return within 10 seconds after SIGTERM")
	}

	capMu.Lock()
	errs := make([]string, len(captured))
	copy(errs, captured)
	capMu.Unlock()

	found := false
	for _, msg := range errs {
		if strings.Contains(msg, "shutdown") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected slog.Error mentioning 'shutdown', got messages: %v", errs)
	}
}

// shutdownErrCapture is a slog.Handler that captures the messages of all
// Error-level log records. It is used by TestServer_Run_ShutdownError to
// verify that the shutdown error branches in Run are exercised.
type shutdownErrCapture struct {
	mu   *sync.Mutex
	msgs *[]string
}

func (h *shutdownErrCapture) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelError
}

func (h *shutdownErrCapture) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	*h.msgs = append(*h.msgs, r.Message)
	h.mu.Unlock()
	return nil
}

func (h *shutdownErrCapture) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *shutdownErrCapture) WithGroup(_ string) slog.Handler      { return h }

// TestServer_Run_MetricsShutdownError verifies that when the metrics server
// cannot drain all active connections within ShutdownTimeout, Run logs
// "metrics server shutdown error" and still returns cleanly. This covers the
// previously-untested slog.Error branch inside the concurrent
// metricsServer.Shutdown goroutine in Run (server.go).
//
// The test holds a raw TCP connection to the metrics server that has only sent
// a partial HTTP request line. Go's net/http server marks the connection as
// active as soon as it is accepted, so Server.Shutdown waits for it to drain.
// With a 5 ms ShutdownTimeout the context expires before the ReadHeaderTimeout
// fires, forcing Shutdown to return context.DeadlineExceeded and logging the
// error we want to exercise.
func TestServer_Run_MetricsShutdownError(t *testing.T) {
	// Capture slog.Error calls so we can assert the metrics-shutdown error path.
	var captured []string
	var capMu sync.Mutex
	capHandler := &shutdownErrCapture{mu: &capMu, msgs: &captured}
	old := slog.Default()
	slog.SetDefault(slog.New(capHandler))
	defer slog.SetDefault(old)

	// Grab free local ports for the main and metrics servers. There is a small
	// TOCTOU window, but it matches the pattern already used in TestServer_Run_ShutdownError
	// and is acceptable in tests: the OS does not immediately reuse freed ports.
	l1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("could not bind test port for main server: %v", err)
	}
	mainPort := strconv.Itoa(l1.Addr().(*net.TCPAddr).Port)
	_ = l1.Close()

	l2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("could not bind test port for metrics server: %v", err)
	}
	metricsPort := strconv.Itoa(l2.Addr().(*net.TCPAddr).Port)
	_ = l2.Close()

	srv := NewServer(ServerConfig{
		Port:            mainPort,
		MetricsPort:     metricsPort,
		WorkerCount:     1,
		QueueSize:       5,
		DrainTimeout:    time.Second,
		ShutdownTimeout: 5 * time.Millisecond, // expire fast to force shutdown error
	}, new(AlertMetrics), func(ctx context.Context, alert AlertPayload) {})

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		srv.Run(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	}()

	// Wait for the metrics server to be ready.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err2 := http.Get("http://127.0.0.1:" + metricsPort + "/metrics")
		if err2 == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Open a raw TCP connection to the metrics server and send only the first
	// line of an HTTP request — the server goroutine will block waiting for the
	// remaining headers, keeping the connection in an active (non-idle) state
	// until the ReadHeaderTimeout fires (5 s). With ShutdownTimeout=5 ms, the
	// shutdown context expires long before that, triggering the error path.
	metricsConn, err := net.Dial("tcp", "127.0.0.1:"+metricsPort)
	if err != nil {
		t.Fatalf("failed to connect to metrics server: %v", err)
	}
	defer metricsConn.Close()
	if _, err = metricsConn.Write([]byte("GET /metrics HTTP/1.1\r\n")); err != nil {
		t.Fatalf("failed to write partial request: %v", err)
	}
	// Allow the server goroutine to accept the connection and start reading.
	time.Sleep(30 * time.Millisecond)

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}

	select {
	case <-runDone:
		// Run returned — shutdown completed despite the hanging metrics connection.
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return within 10 seconds after SIGTERM")
	}

	capMu.Lock()
	errs := make([]string, len(captured))
	copy(errs, captured)
	capMu.Unlock()

	found := false
	for _, msg := range errs {
		if strings.Contains(msg, "metrics server shutdown error") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected slog.Error mentioning 'metrics server shutdown error', got messages: %v", errs)
	}
}

// TestServer_Run_DefaultMetricsPort verifies that when ServerConfig.MetricsPort
// is empty Run falls back to port 9101. This covers the previously-untested
// `metricsPort = "9101"` branch in Run (server.go). The test is skipped when
// port 9101 is already in use so it does not flake in environments where the
// port is occupied by another service.
func TestServer_Run_DefaultMetricsPort(t *testing.T) {
	// Check port availability before attempting to bind; skip rather than fail.
	probe, err := net.Listen("tcp", "127.0.0.1:9101")
	if err != nil {
		t.Skipf("port 9101 not available, skipping default-metrics-port test: %v", err)
	}
	_ = probe.Close()

	srv := NewServer(ServerConfig{
		Port:            "0",    // OS-assigned main port
		MetricsPort:     "",     // intentionally empty — exercises the "9101" default
		WorkerCount:     1,
		QueueSize:       5,
		DrainTimeout:    time.Second,
		ShutdownTimeout: 50 * time.Millisecond,
	}, new(AlertMetrics), func(ctx context.Context, alert AlertPayload) {})

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		srv.Run(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	}()

	// Verify the metrics server is reachable on the default port 9101.
	deadline := time.Now().Add(2 * time.Second)
	started := false
	for time.Now().Before(deadline) {
		resp, err2 := http.Get("http://127.0.0.1:9101/metrics")
		if err2 == nil {
			resp.Body.Close()
			started = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !started {
		t.Error("metrics server did not become reachable on default port 9101")
	}

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}

	select {
	case <-runDone:
		// Run returned cleanly — default metrics port path exercised.
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return within 10 seconds after SIGTERM")
	}
}
