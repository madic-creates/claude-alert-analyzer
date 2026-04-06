package shared

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

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

	cfg := BaseConfig{APIBaseURL: srv.URL, APIKey: "test-key", ClaudeModel: "test"}
	tools := []Tool{{Name: "execute_command", Description: "test", InputSchema: InputSchema{Type: "object"}}}

	result, err := RunToolLoop(context.Background(), cfg, "system", "user prompt", tools, 10,
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

	cfg := BaseConfig{APIBaseURL: srv.URL, APIKey: "test-key", ClaudeModel: "test"}
	tools := []Tool{{Name: "execute_command", Description: "test", InputSchema: InputSchema{Type: "object"}}}

	var toolCalls int
	result, err := RunToolLoop(context.Background(), cfg, "system", "user prompt", tools, 10,
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

		var reqBody ToolRequest
		json.NewDecoder(r.Body).Decode(&reqBody)

		// If no tools in request, Claude must produce text
		if len(reqBody.Tools) == 0 {
			fmt.Fprint(w, `{
				"content": [{"type": "text", "text": "Forced summary after max rounds."}],
				"stop_reason": "end_turn",
				"usage": {"input_tokens": 200, "output_tokens": 50}
			}`)
			return
		}

		// Always request a tool
		fmt.Fprintf(w, `{
			"content": [
				{"type": "tool_use", "id": "toolu_%d", "name": "execute_command", "input": {"command": ["uptime"]}}
			],
			"stop_reason": "tool_use",
			"usage": {"input_tokens": 50, "output_tokens": 10}
		}`, call)
	}))
	defer srv.Close()

	cfg := BaseConfig{APIBaseURL: srv.URL, APIKey: "test-key", ClaudeModel: "test"}
	tools := []Tool{{Name: "execute_command", Description: "test", InputSchema: InputSchema{Type: "object"}}}

	var toolCalls int
	result, err := RunToolLoop(context.Background(), cfg, "system", "user prompt", tools, 2,
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

	cfg := BaseConfig{APIBaseURL: srv.URL, APIKey: "test-key", ClaudeModel: "test"}
	tools := []Tool{{Name: "execute_command", Description: "test", InputSchema: InputSchema{Type: "object"}}}

	_, err := RunToolLoop(context.Background(), cfg, "system", "user prompt", tools, 10,
		func(name string, input json.RawMessage) (string, error) { return "", nil })

	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}
