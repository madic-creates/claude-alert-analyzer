package shared

import (
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
