package shared

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
)

// toolUseResponse returns a Messages API response body requesting one tool call.
func toolUseResponse(id string) string {
	return fmt.Sprintf(`{
		"content": [
			{"type": "tool_use", "id": %q, "name": "execute_command", "input": {"command": ["uptime"]}}
		],
		"stop_reason": "tool_use",
		"usage": {"input_tokens": 50, "output_tokens": 10}
	}`, id)
}

// TestRunToolLoop_BudgetNoticeInjected verifies that once ~75% of the round
// budget is consumed, a "[budget notice]" text block is appended to the
// conversation so the model can prioritize its remaining rounds instead of
// being cut off by the forced summary. With maxRounds=4 the notice fires after
// round 3 (ceil(0.75*4)=3), so it must appear in request 4 and not before.
func TestRunToolLoop_BudgetNoticeInjected(t *testing.T) {
	var callCount atomic.Int32
	var mu sync.Mutex
	var bodies []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := callCount.Add(1)
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(raw))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if call <= 3 {
			fmt.Fprint(w, toolUseResponse(fmt.Sprintf("toolu_%d", call)))
			return
		}
		fmt.Fprint(w, `{
			"content": [{"type": "text", "text": "Final analysis."}],
			"stop_reason": "end_turn",
			"usage": {"input_tokens": 200, "output_tokens": 40}
		}`)
	}))
	defer srv.Close()

	client := newTestClient(t, srv, "test", "test-key", 0)
	tools := []anthropic.ToolUnionParam{{OfTool: &anthropic.ToolParam{Name: "execute_command"}}}

	result, _, _, err := client.RunToolLoop(context.Background(), SeverityWarning, "test-model", "system", "user prompt", tools, 4,
		func(name string, input json.RawMessage) (string, error) { return "load: 0.1", nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "Final analysis." {
		t.Errorf("unexpected result: %q", result)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 4 {
		t.Fatalf("expected 4 API requests, got %d", len(bodies))
	}
	for i, body := range bodies[:3] {
		if strings.Contains(body, "[budget notice]") {
			t.Errorf("request %d must not contain the budget notice yet", i+1)
		}
	}
	last := bodies[3]
	if got := strings.Count(last, "[budget notice]"); got != 1 {
		t.Fatalf("request 4 should contain exactly one budget notice, got %d; body:\n%s", got, last)
	}
	if !strings.Contains(last, "3 of 4 tool rounds") {
		t.Errorf("budget notice should state used/total rounds; body:\n%s", last)
	}
	if !strings.Contains(last, "1 remain") {
		t.Errorf("budget notice should state remaining rounds; body:\n%s", last)
	}
}

// TestRunToolLoop_BudgetNoticePersistsAndStaysSingle verifies that with a
// 10-round budget the notice fires after round 8 (2 remaining, per issue #35)
// and, once injected, is not duplicated on later rounds.
func TestRunToolLoop_BudgetNoticeFiresAtSeventyFivePercentOfTen(t *testing.T) {
	var callCount atomic.Int32
	var mu sync.Mutex
	var bodies []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := callCount.Add(1)
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(raw))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if call <= 9 {
			fmt.Fprint(w, toolUseResponse(fmt.Sprintf("toolu_%d", call)))
			return
		}
		fmt.Fprint(w, `{
			"content": [{"type": "text", "text": "Done."}],
			"stop_reason": "end_turn",
			"usage": {"input_tokens": 200, "output_tokens": 40}
		}`)
	}))
	defer srv.Close()

	client := newTestClient(t, srv, "test", "test-key", 0)
	tools := []anthropic.ToolUnionParam{{OfTool: &anthropic.ToolParam{Name: "execute_command"}}}

	_, _, _, err := client.RunToolLoop(context.Background(), SeverityWarning, "test-model", "system", "user prompt", tools, 10,
		func(name string, input json.RawMessage) (string, error) { return "ok", nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 10 {
		t.Fatalf("expected 10 API requests, got %d", len(bodies))
	}
	// Requests 1-8 precede the injection (notice fires after round 8 completes).
	for i, body := range bodies[:8] {
		if strings.Contains(body, "[budget notice]") {
			t.Errorf("request %d must not contain the budget notice yet", i+1)
		}
	}
	// Requests 9 and 10 carry the notice exactly once (it stays in history
	// but must never be appended a second time).
	for i, body := range bodies[8:] {
		if got := strings.Count(body, "[budget notice]"); got != 1 {
			t.Errorf("request %d should contain exactly one budget notice, got %d", i+9, got)
		}
	}
	if !strings.Contains(bodies[8], "8 of 10 tool rounds") || !strings.Contains(bodies[8], "2 remain") {
		t.Errorf("budget notice should say 8 of 10 used, 2 remaining; body:\n%s", bodies[8])
	}
}

// TestRunToolLoop_BudgetNoticeSkippedForSmallBudget verifies that budgets too
// small to benefit (warning round would equal the final round) never inject a
// notice — the forced-summary prompt already covers the cutoff there.
func TestRunToolLoop_BudgetNoticeSkippedForSmallBudget(t *testing.T) {
	var callCount atomic.Int32
	var mu sync.Mutex
	var bodies []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := callCount.Add(1)
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(raw))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if call <= 2 {
			fmt.Fprint(w, toolUseResponse(fmt.Sprintf("toolu_%d", call)))
			return
		}
		// call 3 = forced summary after maxRounds=2.
		fmt.Fprint(w, `{
			"content": [{"type": "text", "text": "Summary."}],
			"stop_reason": "end_turn",
			"usage": {"input_tokens": 200, "output_tokens": 40}
		}`)
	}))
	defer srv.Close()

	client := newTestClient(t, srv, "test", "test-key", 0)
	tools := []anthropic.ToolUnionParam{{OfTool: &anthropic.ToolParam{Name: "execute_command"}}}

	_, _, _, err := client.RunToolLoop(context.Background(), SeverityWarning, "test-model", "system", "user prompt", tools, 2,
		func(name string, input json.RawMessage) (string, error) { return "ok", nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	for i, body := range bodies {
		if strings.Contains(body, "[budget notice]") {
			t.Errorf("request %d must not contain a budget notice for maxRounds=2", i+1)
		}
	}
}
