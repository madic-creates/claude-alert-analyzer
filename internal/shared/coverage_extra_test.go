package shared

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
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
