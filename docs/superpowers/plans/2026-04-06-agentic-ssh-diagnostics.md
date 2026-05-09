# Agentic SSH Diagnostics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace static SSH diagnostic commands with an agentic Claude tool-use loop where Claude freely chooses which commands to run (max 10 rounds) and produces the analysis directly.

**Architecture:** Extend `shared/` with Claude tool-use types and a generic `RunToolLoop()` function. Create `checkmk/agent.go` with denylist, tool handler, and `RunAgenticDiagnostics()`. Slim down `ssh.go` to SSH primitives only. Wire the agentic loop into `processAlert()` replacing both `GatherContext(SSH)` and `AnalyzeWithClaude()`.

**Tech Stack:** Go 1.26, Claude Messages API with tool_use, golang.org/x/crypto/ssh

---

### Task 1: Extend shared types with tool-use support

**Files:**
- Modify: `internal/shared/types.go`
- Test: `internal/shared/types_test.go`

- [ ] **Step 1: Write tests for new types and serialization**

Create `internal/shared/types_test.go`:

```go
package shared

import (
	"encoding/json"
	"testing"
)

func TestToolRequestJSON(t *testing.T) {
	req := ToolRequest{
		Model:     "claude-sonnet-4-6",
		MaxTokens: 2048,
		System:    "You are an SRE.",
		Tools: []Tool{{
			Name:        "execute_command",
			Description: "Run a command via SSH",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"command": {Type: "array", Description: "Command argv"},
				},
				Required: []string{"command"},
			},
		}},
		Messages: []ToolMessage{{
			Role:    "user",
			Content: "Investigate this alert.",
		}},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	tools := parsed["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}
	tool := tools[0].(map[string]any)
	if tool["name"] != "execute_command" {
		t.Errorf("expected tool name execute_command, got %v", tool["name"])
	}
}

func TestToolMessageJSON_StringContent(t *testing.T) {
	msg := ToolMessage{Role: "user", Content: "hello"}
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var parsed map[string]any
	json.Unmarshal(data, &parsed)
	if parsed["content"] != "hello" {
		t.Errorf("expected string content, got %v", parsed["content"])
	}
}

func TestToolMessageJSON_BlockContent(t *testing.T) {
	msg := ToolMessage{
		Role: "user",
		Content: []ContentBlock{
			{Type: "tool_result", ToolUseID: "toolu_123", Content: "output here"},
		},
	}
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var parsed map[string]any
	json.Unmarshal(data, &parsed)
	blocks := parsed["content"].([]any)
	if len(blocks) != 1 {
		t.Fatalf("expected 1 block, got %d", len(blocks))
	}
	block := blocks[0].(map[string]any)
	if block["type"] != "tool_result" {
		t.Errorf("expected tool_result, got %v", block["type"])
	}
}

func TestToolResponseParse_EndTurn(t *testing.T) {
	raw := `{
		"content": [{"type": "text", "text": "Analysis complete."}],
		"stop_reason": "end_turn",
		"usage": {"input_tokens": 100, "output_tokens": 50}
	}`
	var resp ToolResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.StopReason != "end_turn" {
		t.Errorf("expected end_turn, got %s", resp.StopReason)
	}
	if len(resp.Content) != 1 || resp.Content[0].Text != "Analysis complete." {
		t.Error("unexpected content")
	}
}

func TestToolResponseParse_ToolUse(t *testing.T) {
	raw := `{
		"content": [
			{"type": "text", "text": "Let me check disk usage."},
			{"type": "tool_use", "id": "toolu_abc", "name": "execute_command", "input": {"command": ["df", "-h"]}}
		],
		"stop_reason": "tool_use",
		"usage": {"input_tokens": 200, "output_tokens": 80}
	}`
	var resp ToolResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.StopReason != "tool_use" {
		t.Errorf("expected tool_use, got %s", resp.StopReason)
	}
	if len(resp.Content) != 2 {
		t.Fatalf("expected 2 blocks, got %d", len(resp.Content))
	}
	toolBlock := resp.Content[1]
	if toolBlock.Name != "execute_command" || toolBlock.ID != "toolu_abc" {
		t.Error("unexpected tool_use block")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/shared/ -run TestTool -v`
Expected: compilation errors (types don't exist yet)

- [ ] **Step 3: Add tool-use types to types.go**

Add to the end of `internal/shared/types.go`:

```go
// Tool-use types for agentic Claude interactions.

type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema InputSchema `json:"input_schema"`
}

type InputSchema struct {
	Type       string              `json:"type"`
	Properties map[string]Property `json:"properties"`
	Required   []string            `json:"required"`
}

type Property struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Items       *Items `json:"items,omitempty"`
}

type Items struct {
	Type string `json:"type"`
}

type ContentBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text,omitempty"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Content   string          `json:"content,omitempty"`
}

// ToolMessage supports both string content (user/assistant text) and
// []ContentBlock content (tool_use responses, tool_result messages).
type ToolMessage struct {
	Role    string `json:"role"`
	Content any    `json:"content"` // string or []ContentBlock
}

// ToolRequest is the Claude Messages API request with tool support.
type ToolRequest struct {
	Model     string        `json:"model"`
	MaxTokens int           `json:"max_tokens"`
	System    string        `json:"system"`
	Tools     []Tool        `json:"tools,omitempty"`
	Messages  []ToolMessage `json:"messages"`
}

// ToolResponse is the Claude Messages API response with tool-use support.
type ToolResponse struct {
	Content    []ContentBlock `json:"content"`
	StopReason string         `json:"stop_reason"`
	Usage      struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}
```

Add `"encoding/json"` to the imports at the top of `types.go`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/shared/ -run TestTool -v`
Expected: all 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add internal/shared/types.go internal/shared/types_test.go
git commit -m "feat: add Claude tool-use types for agentic interactions"
```

---

### Task 2: Extract sendRequest helper and add RunToolLoop

**Files:**
- Modify: `internal/shared/claude.go`
- Create: `internal/shared/claude_test.go`

- [ ] **Step 1: Write tests for RunToolLoop**

Create `internal/shared/claude_test.go`:

```go
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/shared/ -run TestRunToolLoop -v`
Expected: compilation error (RunToolLoop doesn't exist)

- [ ] **Step 3: Extract sendRequest and implement RunToolLoop**

Rewrite `internal/shared/claude.go`:

```go
package shared

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const anthropicVersion = "2023-06-01"

var claudeHTTPClient = &http.Client{Timeout: 120 * time.Second}

// sendRequest sends a JSON body to the Claude API and returns the raw response bytes.
func sendRequest(ctx context.Context, cfg BaseConfig, body any) ([]byte, error) {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", cfg.APIBaseURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	if strings.Contains(cfg.APIBaseURL, "anthropic.com") {
		req.Header.Set("x-api-key", cfg.APIKey)
		req.Header.Set("anthropic-version", anthropicVersion)
	} else {
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	}

	resp, err := claudeHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned %d: %s", resp.StatusCode, Truncate(string(respBody), 300))
	}

	return respBody, nil
}

// AnalyzeWithClaude sends a single-turn analysis request. Used by k8s-analyzer.
func AnalyzeWithClaude(ctx context.Context, cfg BaseConfig, systemPrompt, userPrompt string) (string, error) {
	reqBody := ClaudeRequest{
		Model:     cfg.ClaudeModel,
		MaxTokens: 2048,
		System:    systemPrompt,
		Messages:  []ClaudeMessage{{Role: "user", Content: userPrompt}},
	}

	respBody, err := sendRequest(ctx, cfg, reqBody)
	if err != nil {
		return "", err
	}

	var result ClaudeResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}

	if result.Error != nil {
		return "", fmt.Errorf("API error: %s: %s", result.Error.Type, result.Error.Message)
	}

	var parts []string
	for _, c := range result.Content {
		if c.Type == "text" && c.Text != "" {
			parts = append(parts, c.Text)
		}
	}

	slog.Info("Claude analysis complete",
		"model", cfg.ClaudeModel,
		"inputTokens", result.Usage.InputTokens,
		"outputTokens", result.Usage.OutputTokens)

	return strings.Join(parts, "\n"), nil
}

// RunToolLoop runs a multi-turn Claude conversation with tool use.
// handleTool is called for each tool_use block. After maxRounds of tool calls,
// a final request without tools forces Claude to produce a text response.
func RunToolLoop(
	ctx context.Context,
	cfg BaseConfig,
	systemPrompt string,
	userPrompt string,
	tools []Tool,
	maxRounds int,
	handleTool func(name string, input json.RawMessage) (string, error),
) (string, error) {
	messages := []ToolMessage{{Role: "user", Content: userPrompt}}

	var totalInput, totalOutput int

	for round := range maxRounds {
		slog.Info("tool loop round", "round", round+1, "maxRounds", maxRounds)

		reqBody := ToolRequest{
			Model:     cfg.ClaudeModel,
			MaxTokens: 4096,
			System:    systemPrompt,
			Tools:     tools,
			Messages:  messages,
		}

		respBody, err := sendRequest(ctx, cfg, reqBody)
		if err != nil {
			return "", fmt.Errorf("round %d: %w", round+1, err)
		}

		var resp ToolResponse
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return "", fmt.Errorf("round %d parse: %w", round+1, err)
		}

		if resp.Error != nil {
			return "", fmt.Errorf("round %d API error: %s: %s", round+1, resp.Error.Type, resp.Error.Message)
		}

		totalInput += resp.Usage.InputTokens
		totalOutput += resp.Usage.OutputTokens

		// Append assistant response to conversation
		messages = append(messages, ToolMessage{Role: "assistant", Content: resp.Content})

		if resp.StopReason == "end_turn" {
			slog.Info("tool loop complete",
				"rounds", round+1,
				"totalInputTokens", totalInput,
				"totalOutputTokens", totalOutput)
			return extractText(resp.Content), nil
		}

		// Process tool calls
		var toolResults []ContentBlock
		for _, block := range resp.Content {
			if block.Type != "tool_use" {
				continue
			}

			slog.Info("tool call", "round", round+1, "tool", block.Name, "id", block.ID)
			output, err := handleTool(block.Name, block.Input)
			if err != nil {
				output = fmt.Sprintf("error: %v", err)
			}

			toolResults = append(toolResults, ContentBlock{
				Type:      "tool_result",
				ToolUseID: block.ID,
				Content:   output,
			})
		}

		messages = append(messages, ToolMessage{Role: "user", Content: toolResults})
	}

	// Max rounds reached — send final request without tools to force a text response
	slog.Info("tool loop max rounds reached, requesting summary", "maxRounds", maxRounds)

	reqBody := ToolRequest{
		Model:     cfg.ClaudeModel,
		MaxTokens: 4096,
		System:    systemPrompt,
		Messages:  messages,
	}

	respBody, err := sendRequest(ctx, cfg, reqBody)
	if err != nil {
		return "", fmt.Errorf("summary request: %w", err)
	}

	var resp ToolResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return "", fmt.Errorf("summary parse: %w", err)
	}

	if resp.Error != nil {
		return "", fmt.Errorf("summary API error: %s: %s", resp.Error.Type, resp.Error.Message)
	}

	totalInput += resp.Usage.InputTokens
	totalOutput += resp.Usage.OutputTokens

	slog.Info("tool loop complete (forced summary)",
		"totalRounds", maxRounds,
		"totalInputTokens", totalInput,
		"totalOutputTokens", totalOutput)

	return extractText(resp.Content), nil
}

func extractText(blocks []ContentBlock) string {
	var parts []string
	for _, b := range blocks {
		if b.Type == "text" && b.Text != "" {
			parts = append(parts, b.Text)
		}
	}
	return strings.Join(parts, "\n")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/shared/ -v`
Expected: all tests PASS (both new RunToolLoop tests and existing redact/cooldown tests)

- [ ] **Step 5: Commit**

```bash
git add internal/shared/claude.go internal/shared/claude_test.go
git commit -m "feat: add RunToolLoop for multi-turn Claude tool-use conversations"
```

---

### Task 3: Create agent.go with denylist, tool handler, and agentic diagnostics

**Files:**
- Create: `internal/checkmk/agent.go`
- Create: `internal/checkmk/agent_test.go`

- [ ] **Step 1: Write tests for denylist and tool handler**

Create `internal/checkmk/agent_test.go`:

```go
package checkmk

import (
	"encoding/json"
	"testing"
)

func TestIsDenied_BlocksDestructiveCommands(t *testing.T) {
	denied := [][]string{
		{"rm", "-rf", "/"},
		{"sudo", "cat", "/etc/shadow"},
		{"su", "-", "root"},
		{"shutdown", "-h", "now"},
		{"reboot"},
		{"dd", "if=/dev/zero", "of=/dev/sda"},
		{"chmod", "777", "/etc/passwd"},
		{"kill", "-9", "1"},
		{"mv", "/etc/hosts", "/tmp/"},
		{"iptables", "-F"},
		{"mount", "/dev/sdb1", "/mnt"},
		{"pkexec", "bash"},
		{"doas", "sh"},
		{"passwd", "root"},
		{"crontab", "-e"},
		{"nft", "flush", "ruleset"},
		{"useradd", "hacker"},
		{"chown", "root:root", "/tmp/foo"},
	}
	for _, argv := range denied {
		if !isDenied(argv) {
			t.Errorf("expected denied: %v", argv)
		}
	}
}

func TestIsDenied_AllowsReadOnlyCommands(t *testing.T) {
	allowed := [][]string{
		{"df", "-h"},
		{"free", "-h"},
		{"uptime"},
		{"top", "-bn1"},
		{"ps", "aux", "--sort=-%mem"},
		{"journalctl", "--no-pager", "-p", "err", "-n", "50"},
		{"cat", "/var/log/syslog"},
		{"ls", "-la", "/tmp"},
		{"netstat", "-tlnp"},
		{"ss", "-tlnp"},
		{"ip", "addr"},
		{"du", "-sh", "/var"},
		{"head", "-n", "100", "/var/log/messages"},
		{"tail", "-n", "50", "/var/log/syslog"},
		{"grep", "error", "/var/log/syslog"},
		{"find", "/var/log", "-name", "*.log"},
		{"lsblk"},
		{"lsof", "-i", ":80"},
	}
	for _, argv := range allowed {
		if isDenied(argv) {
			t.Errorf("expected allowed: %v", argv)
		}
	}
}

func TestIsDenied_SystemctlSpecialCases(t *testing.T) {
	allowed := [][]string{
		{"systemctl", "status", "nginx"},
		{"systemctl", "show", "sshd"},
		{"systemctl", "list-units", "--failed"},
		{"systemctl", "is-active", "docker"},
		{"systemctl", "is-failed", "nginx"},
		{"systemctl", "list-timers"},
	}
	for _, argv := range allowed {
		if isDenied(argv) {
			t.Errorf("expected allowed: %v", argv)
		}
	}

	denied := [][]string{
		{"systemctl", "restart", "nginx"},
		{"systemctl", "stop", "sshd"},
		{"systemctl", "start", "docker"},
		{"systemctl", "enable", "foo"},
		{"systemctl", "disable", "bar"},
		{"systemctl", "mask", "firewalld"},
		{"systemctl", "daemon-reload"},
	}
	for _, argv := range denied {
		if !isDenied(argv) {
			t.Errorf("expected denied: %v", argv)
		}
	}
}

func TestIsDenied_EmptyCommand(t *testing.T) {
	if !isDenied(nil) {
		t.Error("expected denied for nil")
	}
	if !isDenied([]string{}) {
		t.Error("expected denied for empty")
	}
}

func TestParseCommandInput(t *testing.T) {
	input := json.RawMessage(`{"command": ["df", "-h"]}`)
	argv, err := parseCommandInput(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(argv) != 2 || argv[0] != "df" || argv[1] != "-h" {
		t.Errorf("unexpected argv: %v", argv)
	}
}

func TestParseCommandInput_Invalid(t *testing.T) {
	cases := []string{
		`{}`,
		`{"command": "not-array"}`,
		`{"command": []}`,
	}
	for _, c := range cases {
		_, err := parseCommandInput(json.RawMessage(c))
		if err == nil {
			t.Errorf("expected error for input: %s", c)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/checkmk/ -run "TestIsDenied|TestParseCommand" -v`
Expected: compilation error (functions don't exist)

- [ ] **Step 3: Create agent.go**

Create `internal/checkmk/agent.go`:

```go
package checkmk

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
)

const agentSystemPrompt = `You are an infrastructure SRE analyst investigating a monitoring alert via SSH.

Your task:
1. Use the execute_command tool to run diagnostic commands on the affected host
2. Analyze the outputs to identify the root cause
3. When you have enough information, stop calling tools and write your analysis

Guidelines:
- Only run read-only diagnostic commands (no modifications, no writes, no restarts)
- You have NO root/sudo access — never attempt privilege escalation
- Start broad (check logs, resource usage) then narrow down based on findings
- You have a maximum of 10 command rounds — use them wisely
- Common useful commands: journalctl, df, free, top, ps, ss, ip, lsblk, cat/tail/head on log files, systemctl status/show, du, lsof, netstat, find

Output your final analysis in markdown (headings, bold, lists, code blocks — no tables):
1. Root cause (most likely explanation based on evidence)
2. Severity and blast radius (other affected services/hosts)
3. Remediation steps (concrete actions, no sudo)
4. Correlations between services if applicable

Reference actual values from command outputs. Keep response under 500 words.`

var sshTool = shared.Tool{
	Name:        "execute_command",
	Description: "Execute a diagnostic command on the remote host via SSH. The command is passed as an argv array (not interpreted by a shell). Only read-only commands are allowed.",
	InputSchema: shared.InputSchema{
		Type: "object",
		Properties: map[string]shared.Property{
			"command": {
				Type:        "array",
				Description: "Command and arguments as array, e.g. [\"df\", \"-h\"] or [\"journalctl\", \"--no-pager\", \"-n\", \"50\"]",
				Items:       &shared.Items{Type: "string"},
			},
		},
		Required: []string{"command"},
	},
}

var deniedCommands = map[string]bool{
	"rm": true, "rmdir": true, "dd": true, "mkfs": true, "mke2fs": true,
	"shutdown": true, "reboot": true, "poweroff": true, "halt": true, "init": true,
	"sudo": true, "su": true, "pkexec": true, "doas": true,
	"chmod": true, "chown": true, "chgrp": true,
	"kill": true, "killall": true, "pkill": true,
	"mv": true, "cp": true, "ln": true,
	"useradd": true, "userdel": true, "usermod": true, "groupadd": true, "groupdel": true,
	"passwd": true, "crontab": true,
	"iptables": true, "ip6tables": true, "nft": true,
	"mount": true, "umount": true,
	"mkswap": true, "swapon": true, "swapoff": true,
	"insmod": true, "rmmod": true, "modprobe": true,
	"systemctl": true, // handled specially below
}

var systemctlReadOnly = map[string]bool{
	"status": true, "show": true, "is-active": true, "is-failed": true,
	"is-enabled": true, "list-units": true, "list-unit-files": true,
	"list-timers": true, "list-sockets": true, "list-dependencies": true,
}

func isDenied(argv []string) bool {
	if len(argv) == 0 {
		return true
	}

	cmd := argv[0]

	// Special case: systemctl with read-only subcommands is allowed
	if cmd == "systemctl" {
		if len(argv) < 2 {
			return true
		}
		return !systemctlReadOnly[argv[1]]
	}

	return deniedCommands[cmd]
}

func parseCommandInput(input json.RawMessage) ([]string, error) {
	var parsed struct {
		Command []string `json:"command"`
	}
	if err := json.Unmarshal(input, &parsed); err != nil {
		return nil, fmt.Errorf("parse command input: %w", err)
	}
	if len(parsed.Command) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	return parsed.Command, nil
}

// RunAgenticDiagnostics opens an SSH connection to the host and runs a Claude tool-use
// loop where Claude freely chooses diagnostic commands. Returns the final analysis text.
func RunAgenticDiagnostics(
	ctx context.Context,
	cfg Config,
	claudeCfg shared.BaseConfig,
	hostname string,
	alertContext string,
	maxRounds int,
) (string, error) {
	slog.Info("starting agentic SSH diagnostics", "hostname", hostname, "maxRounds", maxRounds)

	client, err := dialSSH(cfg, hostname)
	if err != nil {
		return "", fmt.Errorf("SSH connection failed: %w", err)
	}
	defer client.Close()
	slog.Info("SSH connected for agentic diagnostics", "hostname", hostname)

	handleTool := func(name string, input json.RawMessage) (string, error) {
		if name != "execute_command" {
			return "", fmt.Errorf("unknown tool: %s", name)
		}

		argv, err := parseCommandInput(input)
		if err != nil {
			return "", err
		}

		if isDenied(argv) {
			cmdStr := strings.Join(argv, " ")
			slog.Warn("denied command", "hostname", hostname, "command", cmdStr)
			return fmt.Sprintf("Command denied: %q is not allowed (destructive or privileged command)", argv[0]), nil
		}

		cmdStr := strings.Join(argv, " ")
		slog.Info("agentic SSH command", "hostname", hostname, "command", cmdStr)

		output, err := runSSHCommand(client, argv, 10*time.Second)
		if err != nil {
			slog.Warn("agentic SSH command failed", "hostname", hostname, "command", cmdStr, "error", err)
			return fmt.Sprintf("Command failed: %v", err), nil
		}

		output = shared.RedactSecrets(output)
		output = shared.Truncate(output, 4096)

		return fmt.Sprintf("$ %s\n%s", cmdStr, output), nil
	}

	analysis, err := shared.RunToolLoop(
		ctx, claudeCfg, agentSystemPrompt, alertContext,
		[]shared.Tool{sshTool}, maxRounds, handleTool,
	)
	if err != nil {
		return "", fmt.Errorf("agentic loop failed: %w", err)
	}

	slog.Info("agentic diagnostics complete", "hostname", hostname)
	return analysis, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/checkmk/ -run "TestIsDenied|TestParseCommand" -v`
Expected: all tests PASS

- [ ] **Step 5: Commit**

```bash
git add internal/checkmk/agent.go internal/checkmk/agent_test.go
git commit -m "feat: add agentic SSH diagnostics with command denylist and tool-use loop"
```

---

### Task 4: Slim down ssh.go — remove static command logic

**Files:**
- Modify: `internal/checkmk/ssh.go`
- Modify: `internal/checkmk/ssh_test.go`

- [ ] **Step 1: Replace ssh.go with SSH primitives only**

Replace `internal/checkmk/ssh.go` with:

```go
package checkmk

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func dialSSH(cfg Config, hostAddress string) (*ssh.Client, error) {
	keyBytes, err := os.ReadFile(cfg.SSHKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read SSH key: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse SSH key: %w", err)
	}

	hostKeyCallback, err := knownhosts.New(cfg.SSHKnownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts: %w", err)
	}

	sshCfg := &ssh.ClientConfig{
		User:            cfg.SSHUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
	}

	addr := net.JoinHostPort(hostAddress, "22")
	client, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		return nil, fmt.Errorf("SSH dial %s: %w", addr, err)
	}
	return client, nil
}

func runSSHCommand(client *ssh.Client, argv []string, timeout time.Duration) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("new session: %w", err)
	}
	defer session.Close()

	cmdStr := strings.Join(argv, " ")

	done := make(chan struct{})
	var output []byte
	var cmdErr error

	go func() {
		output, cmdErr = session.CombinedOutput(cmdStr)
		close(done)
	}()

	select {
	case <-done:
		return string(output), cmdErr
	case <-time.After(timeout):
		session.Close()
		return "", fmt.Errorf("timeout after %v", timeout)
	}
}
```

- [ ] **Step 2: Replace ssh_test.go with denylist-focused tests**

Replace `internal/checkmk/ssh_test.go` with:

```go
package checkmk

import "testing"

// SSH primitive tests are integration-level (require SSH server).
// Unit tests for command validation are in agent_test.go.

func TestDialSSH_MissingKeyFile(t *testing.T) {
	cfg := Config{
		SSHKeyPath:        "/nonexistent/key",
		SSHKnownHostsPath: "/nonexistent/known_hosts",
		SSHUser:           "test",
	}
	_, err := dialSSH(cfg, "localhost")
	if err == nil {
		t.Error("expected error for missing key file")
	}
}
```

- [ ] **Step 3: Run all tests**

Run: `go test ./internal/checkmk/ -v`
Expected: all tests PASS

- [ ] **Step 4: Commit**

```bash
git add internal/checkmk/ssh.go internal/checkmk/ssh_test.go
git commit -m "refactor: slim ssh.go to SSH primitives, remove static command logic"
```

---

### Task 5: Update context.go — remove SSH section

**Files:**
- Modify: `internal/checkmk/context.go`
- Modify: `internal/checkmk/context_test.go`

- [ ] **Step 1: Update GatherContext to remove SSH diagnostics**

Replace the `GatherContext` function in `internal/checkmk/context.go` (lines 135-182) with:

```go
// GatherContext collects alert details and CheckMK host services.
// SSH diagnostics are handled separately by RunAgenticDiagnostics.
func GatherContext(ctx context.Context, cfg Config, alert shared.AlertPayload) shared.AnalysisContext {
	hostname := alert.Fields["hostname"]
	hostAddress := alert.Fields["host_address"]

	var sections []shared.ContextSection

	sections = append(sections, shared.ContextSection{
		Name: "Alert Details",
		Content: fmt.Sprintf("- Hostname: %s\n- Address: %s\n- Service: %s\n- State: %s\n- Output: %s\n- Type: %s\n- Perf Data: %s",
			hostname, hostAddress, alert.Fields["service_description"],
			alert.Fields["service_state"], alert.Fields["service_output"],
			alert.Fields["notification_type"], alert.Fields["perf_data"]),
	})

	sections = append(sections, shared.ContextSection{
		Name:    "CheckMK Services on Host",
		Content: getHostServices(ctx, cfg, hostname),
	})

	return shared.AnalysisContext{Sections: sections}
}
```

Also remove the `"time"` import from context.go if it's no longer used (it was only used indirectly via ssh). Check: the `checkmkHTTPClient` uses `time.Second` on line 16, so `"time"` stays. Remove the unused imports only.

- [ ] **Step 2: Remove unused imports from context.go**

The `RunDiagnostics` call is gone, so `"log/slog"` is no longer used in `GatherContext`. Check if `slog` is used elsewhere in context.go — it is used in the `validateHost` error path (line 159). So `slog` stays.

Actually, looking at the code: `validateHost` is still in context.go but is no longer called by `GatherContext`. It will be called by `processAlert` in main.go before `RunAgenticDiagnostics`. So `validateHost` stays as an exported function.

Export `validateHost` by renaming it to `ValidateHost`:

In `internal/checkmk/context.go`, rename `validateHost` to `ValidateHost` (line 46).

- [ ] **Step 3: Update context_test.go**

The existing tests test `validateHost` which is now `ValidateHost`. Update `internal/checkmk/context_test.go`:

Replace all occurrences of `validateHost(` with `ValidateHost(`.

- [ ] **Step 4: Run all tests**

Run: `go test ./internal/checkmk/ -v`
Expected: all tests PASS

- [ ] **Step 5: Commit**

```bash
git add internal/checkmk/context.go internal/checkmk/context_test.go
git commit -m "refactor: remove SSH diagnostics from GatherContext, export ValidateHost"
```

---

### Task 6: Wire agentic loop into processAlert

**Files:**
- Modify: `cmd/checkmk-analyzer/main.go`

- [ ] **Step 1: Rewrite processAlert to use agentic diagnostics**

Replace the `processAlert` function and remove the `systemPrompt` const in `cmd/checkmk-analyzer/main.go`:

Remove lines 19-31 (the `systemPrompt` const).

Replace `processAlert` (lines 156-198) with:

```go
func processAlert(ctx context.Context, cfg checkmk.Config, cooldownMgr *shared.CooldownManager, alert shared.AlertPayload) {
	hostname := alert.Fields["hostname"]
	hostAddress := alert.Fields["host_address"]

	slog.Info("processing CheckMK alert",
		"hostname", hostname,
		"service", alert.Fields["service_description"])

	baseCfg := shared.BaseConfig{
		ClaudeModel:      cfg.ClaudeModel,
		APIBaseURL:       cfg.APIBaseURL,
		APIKey:           cfg.APIKey,
		NtfyPublishURL:   cfg.NtfyPublishURL,
		NtfyPublishTopic: cfg.NtfyPublishTopic,
		NtfyPublishToken: cfg.NtfyPublishToken,
	}

	// Gather CheckMK context (alert details + host services)
	actx := checkmk.GatherContext(ctx, cfg, alert)
	alertContext := actx.FormatForPrompt()

	// Validate host before SSH
	var analysis string
	if err := checkmk.ValidateHost(ctx, cfg, hostname, hostAddress); err != nil {
		slog.Warn("host validation failed, running analysis without SSH",
			"error", err,
			"hostname", hostname,
			"host_address", hostAddress,
		)
		// Fall back to non-agentic analysis without SSH
		alertContext += "\n## Note\nSSH diagnostics unavailable: " + err.Error() + "\n"
		var analyzeErr error
		analysis, analyzeErr = shared.AnalyzeWithClaude(ctx, baseCfg, checkmk.AgentSystemPrompt, alertContext)
		if analyzeErr != nil {
			slog.Error("analysis failed", "error", analyzeErr)
			_ = shared.PublishToNtfy(ctx, baseCfg,
				fmt.Sprintf("Analysis FAILED: %s", alert.Title), "5",
				fmt.Sprintf("**Analysis failed** for %s: %v\n\nManual investigation needed.", alert.Title, analyzeErr))
			cooldownMgr.Clear(alert.Fingerprint)
			return
		}
	} else {
		// Run agentic SSH diagnostics (includes analysis)
		var err error
		analysis, err = checkmk.RunAgenticDiagnostics(ctx, cfg, baseCfg, hostname, alertContext, 10)
		if err != nil {
			slog.Error("agentic diagnostics failed", "error", err)
			_ = shared.PublishToNtfy(ctx, baseCfg,
				fmt.Sprintf("Analysis FAILED: %s", alert.Title), "5",
				fmt.Sprintf("**Agentic diagnostics failed** for %s: %v\n\nManual investigation needed.", alert.Title, err))
			cooldownMgr.Clear(alert.Fingerprint)
			return
		}
	}

	priorityMap := map[string]string{"critical": "5", "warning": "4", "unknown": "3", "ok": "2"}
	priority := priorityMap[alert.Severity]
	if priority == "" {
		priority = "3"
	}

	title := fmt.Sprintf("Analysis: %s", alert.Title)
	if err := shared.PublishToNtfy(ctx, baseCfg, title, priority, analysis); err != nil {
		slog.Error("publish failed", "error", err)
		cooldownMgr.Clear(alert.Fingerprint)
		return
	}

	slog.Info("analysis complete", "hostname", hostname, "model", cfg.ClaudeModel)
}
```

This requires exporting `AgentSystemPrompt` from `agent.go`. In `internal/checkmk/agent.go`, rename `agentSystemPrompt` to `AgentSystemPrompt`.

- [ ] **Step 2: Verify build**

Run: `go build ./cmd/checkmk-analyzer/`
Expected: compiles successfully

- [ ] **Step 3: Verify k8s-analyzer is unaffected**

Run: `go build ./cmd/k8s-analyzer/`
Expected: compiles successfully

- [ ] **Step 4: Run all tests**

Run: `go test ./...`
Expected: all tests PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/checkmk-analyzer/main.go internal/checkmk/agent.go
git commit -m "feat: wire agentic SSH diagnostics into checkmk-analyzer processAlert"
```

---

### Task 7: Update README and verify end-to-end

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update README SSH Diagnostics section**

Replace the "SSH Diagnostic Commands" section in README.md with:

```markdown
### SSH Diagnostic Commands

The checkmk-analyzer uses an **agentic approach**: Claude autonomously decides which commands to run on the alerted host via SSH, based on the alert context and previous command outputs. This replaces the old static command list with a dynamic investigation loop (max 10 rounds).

**Allowed:** Any read-only diagnostic command (e.g. `df`, `free`, `top`, `ps`, `journalctl`, `cat`/`tail`/`head` on log files, `ss`, `ip`, `du`, `lsblk`, `lsof`, `find`, `systemctl status/show`, etc.)

**Denied (denylist):** Destructive or state-modifying commands are blocked: `rm`, `dd`, `mkfs`, `shutdown`, `reboot`, `sudo`, `su`, `chmod`, `chown`, `kill`, `mv`, `cp`, `mount`, `iptables`, `passwd`, `crontab`, `systemctl start/stop/restart`, and similar.

Output is redacted (secrets removed) and truncated per command before being sent to Claude.
```

- [ ] **Step 2: Run full test suite**

Run: `go test ./...`
Expected: all tests PASS

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: update README for agentic SSH diagnostics"
```
