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
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestSendRequest_OversizedResponseIsBounded(t *testing.T) {
	// Serve a response body larger than MaxResponseBytes (2 MiB).
	oversized := 3 * 1024 * 1024 // 3 MiB
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		// Write oversized payload of repeated 'A' bytes.
		buf := make([]byte, oversized)
		for i := range buf {
			buf[i] = 'A'
		}
		w.Write(buf)
	}))
	defer srv.Close()

	client := &ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "test-key", Model: "test"}
	body, err := client.sendRequest(context.Background(), map[string]string{"msg": "hi"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(body) > MaxResponseBytes {
		t.Errorf("response should be bounded to %d bytes, got %d", MaxResponseBytes, len(body))
	}
	if len(body) != MaxResponseBytes {
		t.Errorf("expected exactly %d bytes (LimitReader cap), got %d", MaxResponseBytes, len(body))
	}
}

// ---- Analyze tests ----

func TestAnalyze_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"content": [{"type": "text", "text": "Root cause: OOMKilled pod."}],
			"usage": {"input_tokens": 100, "output_tokens": 20}
		}`)
	}))
	defer srv.Close()

	client := &ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "test-key", Model: "claude-3"}
	result, err := client.Analyze(context.Background(), "sys prompt", "user prompt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "Root cause: OOMKilled pod." {
		t.Errorf("unexpected result: %q", result)
	}
}

func TestAnalyze_MultipleTextBlocks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"content": [
				{"type": "text", "text": "Part one."},
				{"type": "text", "text": "Part two."}
			],
			"usage": {"input_tokens": 50, "output_tokens": 10}
		}`)
	}))
	defer srv.Close()

	client := &ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "test-key", Model: "claude-3"}
	result, err := client.Analyze(context.Background(), "sys", "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "Part one.\nPart two." {
		t.Errorf("unexpected result: %q", result)
	}
}

func TestAnalyze_EmptyContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"content": [],
			"usage": {"input_tokens": 10, "output_tokens": 0}
		}`)
	}))
	defer srv.Close()

	client := &ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "test-key", Model: "claude-3"}
	result, err := client.Analyze(context.Background(), "sys", "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty result, got %q", result)
	}
}

func TestAnalyze_NonTextBlocksIgnored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// A tool_use block mixed with text; only text should be returned
		fmt.Fprint(w, `{
			"content": [
				{"type": "tool_use", "id": "tu_1", "name": "some_tool", "input": {}},
				{"type": "text", "text": "Analysis result."}
			],
			"usage": {"input_tokens": 20, "output_tokens": 5}
		}`)
	}))
	defer srv.Close()

	client := &ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "test-key", Model: "claude-3"}
	result, err := client.Analyze(context.Background(), "sys", "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "Analysis result." {
		t.Errorf("unexpected result: %q", result)
	}
}

func TestAnalyze_APIErrorInBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"error": {"type": "invalid_request_error", "message": "model not found"},
			"content": []
		}`)
	}))
	defer srv.Close()

	client := &ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "test-key", Model: "bad-model"}
	_, err := client.Analyze(context.Background(), "sys", "user")
	if err == nil {
		t.Fatal("expected error for API error body")
	}
	if !strings.Contains(err.Error(), "invalid_request_error") {
		t.Errorf("error should mention error type, got: %v", err)
	}
	if !strings.Contains(err.Error(), "model not found") {
		t.Errorf("error should mention error message, got: %v", err)
	}
}

func TestAnalyze_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, "rate limited")
	}))
	defer srv.Close()

	client := &ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "test-key", Model: "claude-3"}
	_, err := client.Analyze(context.Background(), "sys", "user")
	if err == nil {
		t.Fatal("expected error for non-200 response")
	}
	if !strings.Contains(err.Error(), "429") {
		t.Errorf("error should contain status code, got: %v", err)
	}
}

func TestAnalyze_AnthropicAuthHeader(t *testing.T) {
	var capturedAPIKey, capturedVersion, capturedAuthHeader string
	srvAnthropic := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAPIKey = r.Header.Get("x-api-key")
		capturedVersion = r.Header.Get("anthropic-version")
		capturedAuthHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"content": [{"type": "text", "text": "ok"}], "usage": {}}`)
	}))
	defer srvAnthropic.Close()

	// Use a custom transport that redirects to the test server while keeping
	// the Anthropic URL for header detection.
	client := &ClaudeClient{
		HTTP:    &http.Client{Transport: rewriteHostTransport{target: srvAnthropic.URL}, Timeout: 5 * time.Second},
		BaseURL: "https://api.anthropic.com/v1/messages",
		APIKey:  "anthropic-secret",
		Model:   "claude-3",
	}
	_, err := client.Analyze(context.Background(), "sys", "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedAPIKey != "anthropic-secret" {
		t.Errorf("expected x-api-key header, got %q", capturedAPIKey)
	}
	if capturedVersion != anthropicVersion {
		t.Errorf("expected anthropic-version header %q, got %q", anthropicVersion, capturedVersion)
	}
	if capturedAuthHeader != "" {
		t.Errorf("Authorization header should not be set for Anthropic, got %q", capturedAuthHeader)
	}
}

func TestAnalyze_OpenRouterAuthHeader(t *testing.T) {
	var capturedAuth, capturedAPIKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		capturedAPIKey = r.Header.Get("x-api-key")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"content": [{"type": "text", "text": "ok"}], "usage": {}}`)
	}))
	defer srv.Close()

	// srv.URL does not contain "anthropic.com" so OpenRouter branch fires.
	client := &ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "openrouter-key", Model: "claude-3"}
	_, err := client.Analyze(context.Background(), "sys", "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedAuth != "Bearer openrouter-key" {
		t.Errorf("expected Bearer auth, got %q", capturedAuth)
	}
	if capturedAPIKey != "" {
		t.Errorf("x-api-key should not be set for OpenRouter, got %q", capturedAPIKey)
	}
}

func TestAnalyze_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Never responds — context should cancel the request.
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	client := &ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "test-key", Model: "claude-3"}
	_, err := client.Analyze(ctx, "sys", "user")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

// rewriteHostTransport redirects all requests to a fixed target URL, allowing
// test servers to intercept requests nominally sent to external URLs
// (e.g., api.anthropic.com).
type rewriteHostTransport struct {
	target string // e.g. "http://127.0.0.1:PORT"
}

func (t rewriteHostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	targetURL := t.target + req.URL.Path
	if req.URL.RawQuery != "" {
		targetURL += "?" + req.URL.RawQuery
	}
	newReq := req.Clone(req.Context())
	newReq.URL, _ = req.URL.Parse(targetURL)
	newReq.Host = newReq.URL.Host
	return http.DefaultTransport.RoundTrip(newReq)
}

func TestRunToolLoop_EndTurnImmediately(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := `{
			"content": [{"type": "text", "text": "No tools needed."}],
			"stop_reason": "end_turn",
			"usage": {"input_tokens": 10, "output_tokens": 5}
		}`
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, resp)
	}))
	defer srv.Close()

	client := &ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "test-key", Model: "test"}
	tools := []Tool{{Name: "execute_command", Description: "test", InputSchema: InputSchema{Type: "object"}}}

	result, err := client.RunToolLoop(context.Background(), "system", "user prompt", tools, 10,
		func(name string, input json.RawMessage) (string, error) {
			t.Fatal("tool handler should not be called")
			return "", nil
		})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "No tools needed." {
		t.Errorf("unexpected result: %s", result)
	}
}

func TestRunToolLoop_OneToolRoundThenEnd(t *testing.T) {
	var callCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")

		if call == 1 {
			fmt.Fprint(w, `{
				"content": [
					{"type": "text", "text": "Checking disk."},
					{"type": "tool_use", "id": "toolu_1", "name": "execute_command", "input": {"command": ["df", "-h"]}}
				],
				"stop_reason": "tool_use",
				"usage": {"input_tokens": 50, "output_tokens": 20}
			}`)
		} else {
			fmt.Fprint(w, `{
				"content": [{"type": "text", "text": "Disk is 95% full on /var."}],
				"stop_reason": "end_turn",
				"usage": {"input_tokens": 100, "output_tokens": 30}
			}`)
		}
	}))
	defer srv.Close()

	client := &ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "test-key", Model: "test"}
	tools := []Tool{{Name: "execute_command", Description: "test", InputSchema: InputSchema{Type: "object"}}}

	var toolCalls int
	result, err := client.RunToolLoop(context.Background(), "system", "user prompt", tools, 10,
		func(name string, input json.RawMessage) (string, error) {
			toolCalls++
			if name != "execute_command" {
				t.Errorf("unexpected tool: %s", name)
			}
			return "/dev/sda1  50G  47G  3G  95% /var", nil
		})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if toolCalls != 1 {
		t.Errorf("expected 1 tool call, got %d", toolCalls)
	}
	if result != "Disk is 95% full on /var." {
		t.Errorf("unexpected result: %s", result)
	}
}

func TestRunToolLoop_MaxRoundsForcesSummary(t *testing.T) {
	var callCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")

		// Call 3 = forced summary (after 2 tool rounds with maxRounds=2)
		if call == 3 {
			fmt.Fprint(w, `{
				"content": [{"type": "text", "text": "Forced summary after max rounds."}],
				"stop_reason": "end_turn",
				"usage": {"input_tokens": 200, "output_tokens": 50}
			}`)
			return
		}

		// Rounds 1-2: always request a tool
		fmt.Fprintf(w, `{
			"content": [
				{"type": "tool_use", "id": "toolu_%d", "name": "execute_command", "input": {"command": ["uptime"]}}
			],
			"stop_reason": "tool_use",
			"usage": {"input_tokens": 50, "output_tokens": 10}
		}`, call)
	}))
	defer srv.Close()

	client := &ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "test-key", Model: "test"}
	tools := []Tool{{Name: "execute_command", Description: "test", InputSchema: InputSchema{Type: "object"}}}

	var toolCalls int
	result, err := client.RunToolLoop(context.Background(), "system", "user prompt", tools, 2,
		func(name string, input json.RawMessage) (string, error) {
			toolCalls++
			return "up 5 days", nil
		})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if toolCalls != 2 {
		t.Errorf("expected 2 tool calls, got %d", toolCalls)
	}
	if result != "Forced summary after max rounds." {
		t.Errorf("unexpected result: %s", result)
	}
}

func TestRunToolLoop_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "internal error")
	}))
	defer srv.Close()

	client := &ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "test-key", Model: "test"}
	tools := []Tool{{Name: "execute_command", Description: "test", InputSchema: InputSchema{Type: "object"}}}

	_, err := client.RunToolLoop(context.Background(), "system", "user prompt", tools, 10,
		func(name string, input json.RawMessage) (string, error) { return "", nil })

	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestRunToolLoop_APIErrorInBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"error": {"type": "overloaded_error", "message": "Service temporarily overloaded"},
			"content": []
		}`)
	}))
	defer srv.Close()

	client := &ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "test-key", Model: "test"}
	tools := []Tool{{Name: "execute_command", Description: "test", InputSchema: InputSchema{Type: "object"}}}

	_, err := client.RunToolLoop(context.Background(), "system", "user prompt", tools, 10,
		func(name string, input json.RawMessage) (string, error) { return "", nil })

	if err == nil {
		t.Fatal("expected error for API error in body")
	}
	if !strings.Contains(err.Error(), "overloaded_error") {
		t.Errorf("error should mention error type, got: %v", err)
	}
}

func TestRunToolLoop_ToolHandlerError(t *testing.T) {
	var callCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")

		if call == 1 {
			// Return a tool call
			fmt.Fprint(w, `{
				"content": [
					{"type": "tool_use", "id": "toolu_err", "name": "execute_command", "input": {"command": ["bad"]}}
				],
				"stop_reason": "tool_use",
				"usage": {"input_tokens": 20, "output_tokens": 10}
			}`)
		} else {
			// Second call receives the tool_result with the error message
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("failed to decode request body: %v", err)
			}
			msgs, _ := body["messages"].([]any)
			// Last message should be the user message with tool_result
			lastMsg := msgs[len(msgs)-1].(map[string]any)
			content := lastMsg["content"].([]any)
			toolResult := content[0].(map[string]any)
			gotContent, _ := toolResult["content"].(string)
			if !strings.HasPrefix(gotContent, "error:") {
				t.Errorf("tool result content should start with 'error:', got: %q", gotContent)
			}

			fmt.Fprint(w, `{
				"content": [{"type": "text", "text": "Handled tool error gracefully."}],
				"stop_reason": "end_turn",
				"usage": {"input_tokens": 50, "output_tokens": 10}
			}`)
		}
	}))
	defer srv.Close()

	client := &ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "test-key", Model: "test"}
	tools := []Tool{{Name: "execute_command", Description: "test", InputSchema: InputSchema{Type: "object"}}}

	result, err := client.RunToolLoop(context.Background(), "system", "user prompt", tools, 5,
		func(name string, input json.RawMessage) (string, error) {
			return "", fmt.Errorf("command not allowed")
		})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "Handled tool error gracefully." {
		t.Errorf("unexpected result: %q", result)
	}
}

func TestRunToolLoop_MultipleToolsInOneRound(t *testing.T) {
	var callCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")

		if call == 1 {
			// Return two tool calls in one response
			fmt.Fprint(w, `{
				"content": [
					{"type": "tool_use", "id": "toolu_a", "name": "tool_a", "input": {}},
					{"type": "tool_use", "id": "toolu_b", "name": "tool_b", "input": {}}
				],
				"stop_reason": "tool_use",
				"usage": {"input_tokens": 30, "output_tokens": 20}
			}`)
		} else {
			fmt.Fprint(w, `{
				"content": [{"type": "text", "text": "Both tools executed."}],
				"stop_reason": "end_turn",
				"usage": {"input_tokens": 80, "output_tokens": 15}
			}`)
		}
	}))
	defer srv.Close()

	client := &ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "test-key", Model: "test"}
	tools := []Tool{
		{Name: "tool_a", Description: "first", InputSchema: InputSchema{Type: "object"}},
		{Name: "tool_b", Description: "second", InputSchema: InputSchema{Type: "object"}},
	}

	var calledTools []string
	result, err := client.RunToolLoop(context.Background(), "system", "user prompt", tools, 5,
		func(name string, input json.RawMessage) (string, error) {
			calledTools = append(calledTools, name)
			return "ok", nil
		})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(calledTools) != 2 {
		t.Errorf("expected 2 tool calls, got %d: %v", len(calledTools), calledTools)
	}
	if calledTools[0] != "tool_a" || calledTools[1] != "tool_b" {
		t.Errorf("unexpected tool call order: %v", calledTools)
	}
	if result != "Both tools executed." {
		t.Errorf("unexpected result: %q", result)
	}
}

// TestRunToolLoop_MaxTokensStopReason verifies that a "max_tokens" stop reason
// (no tool_use blocks) is treated as a final answer rather than causing the loop
// to append a nil content message and fail on the next API call.
func TestRunToolLoop_MaxTokensStopReason(t *testing.T) {
	var callCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")

		if call == 1 {
			// Model hits token limit mid-response — text only, no tool_use blocks.
			fmt.Fprint(w, `{
				"content": [{"type": "text", "text": "Partial analysis before token limit."}],
				"stop_reason": "max_tokens",
				"usage": {"input_tokens": 100, "output_tokens": 4096}
			}`)
		} else {
			// A second call should never happen; return an error to make the test fail clearly.
			t.Errorf("unexpected second API call (call %d); nil content message was sent", call)
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error": {"type": "invalid_request", "message": "content must not be null"}}`)
		}
	}))
	defer srv.Close()

	client := &ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "test-key", Model: "test"}
	tools := []Tool{{Name: "execute_command", Description: "test", InputSchema: InputSchema{Type: "object"}}}

	result, err := client.RunToolLoop(context.Background(), "system", "user prompt", tools, 10,
		func(name string, input json.RawMessage) (string, error) {
			t.Fatal("tool handler should not be called on max_tokens response")
			return "", nil
		})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "Partial analysis before token limit." {
		t.Errorf("unexpected result: %q", result)
	}
	if callCount.Load() != 1 {
		t.Errorf("expected exactly 1 API call, got %d", callCount.Load())
	}
}

// TestRunToolLoop_MaxRounds_NoConsecutiveUserMessages verifies that when maxRounds is
// exhausted the forced-summary request does NOT contain two consecutive "user" messages.
// Before the fix, the code appended a separate user turn after the last tool_result
// user turn, causing the Anthropic API to reject the request with a 400
// "roles must alternate" error on every real agentic run that reached max rounds.
func TestRunToolLoop_MaxRounds_NoConsecutiveUserMessages(t *testing.T) {
	var callCount atomic.Int32
	var summaryMessages []map[string]any // decoded messages from the final request

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")

		if call == 1 {
			// Round 1 (only round, maxRounds=1): request a tool call.
			fmt.Fprint(w, `{
				"content": [
					{"type": "tool_use", "id": "toolu_1", "name": "execute_command", "input": {"command": ["uptime"]}}
				],
				"stop_reason": "tool_use",
				"usage": {"input_tokens": 50, "output_tokens": 10}
			}`)
		} else {
			// Call 2 = forced summary. Capture the messages array.
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("failed to decode summary request body: %v", err)
			}
			if msgs, ok := body["messages"].([]any); ok {
				for _, m := range msgs {
					if msg, ok := m.(map[string]any); ok {
						summaryMessages = append(summaryMessages, msg)
					}
				}
			}
			fmt.Fprint(w, `{
				"content": [{"type": "text", "text": "Summary after max rounds."}],
				"stop_reason": "end_turn",
				"usage": {"input_tokens": 200, "output_tokens": 40}
			}`)
		}
	}))
	defer srv.Close()

	client := &ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "test-key", Model: "test"}
	tools := []Tool{{Name: "execute_command", Description: "test", InputSchema: InputSchema{Type: "object"}}}

	result, err := client.RunToolLoop(context.Background(), "system", "user prompt", tools, 1,
		func(name string, input json.RawMessage) (string, error) { return "load: 0.1", nil })

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "Summary after max rounds." {
		t.Errorf("unexpected result: %q", result)
	}

	// Assert no consecutive user messages in the summary request.
	for i := 1; i < len(summaryMessages); i++ {
		prevRole, _ := summaryMessages[i-1]["role"].(string)
		currRole, _ := summaryMessages[i]["role"].(string)
		if prevRole == "user" && currRole == "user" {
			t.Errorf("messages[%d] and messages[%d] are both 'user' — API will reject this: %+v",
				i-1, i, summaryMessages)
		}
	}

	// The last user message should contain both tool_result and text blocks.
	lastMsg := summaryMessages[len(summaryMessages)-1]
	lastRole, _ := lastMsg["role"].(string)
	if lastRole != "user" {
		t.Errorf("last message role should be 'user', got %q", lastRole)
	}
	content, _ := lastMsg["content"].([]any)
	var hasToolResult, hasText bool
	for _, block := range content {
		b, _ := block.(map[string]any)
		switch b["type"] {
		case "tool_result":
			hasToolResult = true
		case "text":
			hasText = true
		}
	}
	if !hasToolResult {
		t.Error("last user message should contain a tool_result block")
	}
	if !hasText {
		t.Error("last user message should contain a text block with the summary prompt")
	}
}

func TestRunToolLoop_SummaryRequestFails(t *testing.T) {
	var callCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")

		if call <= 1 {
			// Single tool round (maxRounds=1) exhausted
			fmt.Fprint(w, `{
				"content": [
					{"type": "tool_use", "id": "toolu_1", "name": "execute_command", "input": {}}
				],
				"stop_reason": "tool_use",
				"usage": {"input_tokens": 20, "output_tokens": 10}
			}`)
		} else {
			// Forced summary request fails
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, "service unavailable")
		}
	}))
	defer srv.Close()

	client := &ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "test-key", Model: "test"}
	tools := []Tool{{Name: "execute_command", Description: "test", InputSchema: InputSchema{Type: "object"}}}

	_, err := client.RunToolLoop(context.Background(), "system", "user prompt", tools, 1,
		func(name string, input json.RawMessage) (string, error) { return "ok", nil })

	if err == nil {
		t.Fatal("expected error when summary request fails")
	}
	if !strings.Contains(err.Error(), "summary") {
		t.Errorf("error should mention 'summary', got: %v", err)
	}
}

// TestRunToolLoop_SummaryRequestHasToolChoiceNone verifies that when maxRounds is
// exhausted the forced-summary request includes tool_choice={"type":"none"}.
// Without this, Claude could still call tools in the summary turn; extractText()
// would return "" and the empty-analysis guard would fire a failure notification.
func TestRunToolLoop_SummaryRequestHasToolChoiceNone(t *testing.T) {
	var callCount atomic.Int32
	var summaryToolChoice map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")

		if call == 1 {
			// Round 1 (only round, maxRounds=1): request a tool call.
			fmt.Fprint(w, `{
				"content": [
					{"type": "tool_use", "id": "toolu_1", "name": "execute_command", "input": {"command": ["uptime"]}}
				],
				"stop_reason": "tool_use",
				"usage": {"input_tokens": 50, "output_tokens": 10}
			}`)
		} else {
			// Call 2 = forced summary. Capture tool_choice from the request body.
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("failed to decode summary request body: %v", err)
			}
			if tc, ok := body["tool_choice"].(map[string]any); ok {
				summaryToolChoice = tc
			}
			fmt.Fprint(w, `{
				"content": [{"type": "text", "text": "Summary."}],
				"stop_reason": "end_turn",
				"usage": {"input_tokens": 200, "output_tokens": 20}
			}`)
		}
	}))
	defer srv.Close()

	client := &ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "test-key", Model: "test"}
	tools := []Tool{{Name: "execute_command", Description: "test", InputSchema: InputSchema{Type: "object"}}}

	result, err := client.RunToolLoop(context.Background(), "system", "user prompt", tools, 1,
		func(name string, input json.RawMessage) (string, error) { return "load: 0.1", nil })

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "Summary." {
		t.Errorf("unexpected result: %q", result)
	}
	if summaryToolChoice == nil {
		t.Fatal("summary request did not include tool_choice field")
	}
	if got := summaryToolChoice["type"]; got != "none" {
		t.Errorf("summary request tool_choice.type = %q, want \"none\"", got)
	}
}

// TestRunToolLoop_SummaryAPIErrorInBody verifies that when maxRounds is exhausted
// and the forced-summary response is a 200 OK containing an API error object in the
// body (e.g. an overload error reported inline by the API), the error is returned
// with a "summary API error:" prefix rather than silently producing empty output.
func TestRunToolLoop_SummaryAPIErrorInBody(t *testing.T) {
	var callCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")

		if call == 1 {
			// Round 1 (only round, maxRounds=1): request a tool call.
			fmt.Fprint(w, `{
				"content": [
					{"type": "tool_use", "id": "toolu_1", "name": "execute_command", "input": {"command": ["uptime"]}}
				],
				"stop_reason": "tool_use",
				"usage": {"input_tokens": 50, "output_tokens": 10}
			}`)
		} else {
			// Call 2 = forced summary. Return 200 OK but with an API error in the body.
			fmt.Fprint(w, `{
				"error": {"type": "overloaded_error", "message": "Service temporarily overloaded"},
				"content": []
			}`)
		}
	}))
	defer srv.Close()

	client := &ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "test-key", Model: "test"}
	tools := []Tool{{Name: "execute_command", Description: "test", InputSchema: InputSchema{Type: "object"}}}

	_, err := client.RunToolLoop(context.Background(), "system", "user prompt", tools, 1,
		func(name string, input json.RawMessage) (string, error) { return "load: 0.1", nil })

	if err == nil {
		t.Fatal("expected error when summary response contains API error")
	}
	if !strings.Contains(err.Error(), "summary API error") {
		t.Errorf("error should mention 'summary API error', got: %v", err)
	}
	if !strings.Contains(err.Error(), "overloaded_error") {
		t.Errorf("error should include the API error type, got: %v", err)
	}
}

// TestAnalyze_ParseResponseError verifies that when the Claude API returns a
// 200 OK but with a non-JSON body (e.g. a CDN maintenance page, a load-balancer
// error page, or a half-written response), Analyze propagates a clear
// "parse response" error rather than silently returning empty output. Without
// this the caller would receive ("", nil) and the pipeline would fire a
// failure notification saying "Analysis produced empty result" with no hint
// that the API returned garbage — making the failure much harder to diagnose.
func TestAnalyze_ParseResponseError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		// Simulate a CDN or proxy returning an HTML maintenance page instead of JSON.
		fmt.Fprint(w, `<!DOCTYPE html><html><body>Service Unavailable</body></html>`)
	}))
	defer srv.Close()

	client := &ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "test-key", Model: "claude-3"}
	_, err := client.Analyze(context.Background(), "sys", "user")
	if err == nil {
		t.Fatal("expected error when API returns non-JSON body, got nil")
	}
	if !strings.Contains(err.Error(), "parse response") {
		t.Errorf("error should mention 'parse response', got: %v", err)
	}
}

// TestSendRequest_DurationHistogramObservedOnSuccess verifies that the
// durationHistogram is observed exactly once for a successful round-trip.
// Without this, claude_api_duration_seconds would never increment regardless
// of how many successful API calls are made, making latency invisible.
func TestSendRequest_DurationHistogramObservedOnSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"content": [], "usage": {}}`)
	}))
	defer srv.Close()

	hist := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "test_sendrequest_duration_seconds",
		Help: "test histogram",
	})
	client := &ClaudeClient{
		HTTP:              srv.Client(),
		BaseURL:           srv.URL,
		APIKey:            "test-key",
		Model:             "test",
		durationHistogram: hist,
	}
	if _, err := client.sendRequest(context.Background(), map[string]string{"k": "v"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var m dto.Metric
	if err := hist.Write(&m); err != nil {
		t.Fatalf("read histogram: %v", err)
	}
	if m.Histogram.GetSampleCount() != 1 {
		t.Errorf("expected 1 histogram observation, got %d", m.Histogram.GetSampleCount())
	}
	if m.Histogram.GetSampleSum() <= 0 {
		t.Errorf("expected positive duration sum, got %f", m.Histogram.GetSampleSum())
	}
}

// TestSendRequest_ErrorCounterIncrementedOnHTTPFailure verifies that the
// errorCounter is incremented exactly once when HTTP.Do fails (e.g. network
// error or cancelled context). Without this, claude_api_errors_total would
// stay at zero during API unreachability, making failures invisible to alerts.
func TestSendRequest_ErrorCounterIncrementedOnHTTPFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // block until the client gives up
	}))
	defer srv.Close()

	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "test_sendrequest_errors_total",
		Help: "test error counter",
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately so HTTP.Do fails right away

	client := &ClaudeClient{
		HTTP:         srv.Client(),
		BaseURL:      srv.URL,
		APIKey:       "test-key",
		Model:        "test",
		errorCounter: counter,
	}
	if _, err := client.sendRequest(ctx, map[string]string{"k": "v"}); err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}

	var m dto.Metric
	if err := counter.Write(&m); err != nil {
		t.Fatalf("read counter: %v", err)
	}
	if m.Counter.GetValue() != 1 {
		t.Errorf("expected error counter = 1, got %f", m.Counter.GetValue())
	}
}
