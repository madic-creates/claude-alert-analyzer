# Design Review Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement all improvements from the 2026-04-16 design review: eliminate main.go duplication, extract testable pipelines, replace global HTTP clients with dependency injection, add CI tests/lint, fix security gaps, and improve observability.

**Architecture:** Extract a shared server scaffold (`shared.Server`) and per-analyzer pipeline functions. Replace package-level HTTP clients with struct-based clients injected at startup. Introduce `Analyzer` interface for testing. Add CI test/lint jobs gating Docker builds.

**Tech Stack:** Go 1.26, slog, net/http, sync/atomic, k8s.io/client-go, golang.org/x/crypto/ssh, GitHub Actions

**Spec:** `docs/superpowers/specs/2026-04-16-design-review-improvements.md`

---

## File Structure

### New files

| File | Responsibility |
|------|---------------|
| `internal/shared/config.go` | `EnvOrDefault`, `ParseIntEnv`, `RequireEnv`, `BuildNtfyPublishers` |
| `internal/shared/config_test.go` | Tests for config helpers |
| `internal/shared/interfaces.go` | `Analyzer` and `ToolLoopRunner` interfaces |
| `internal/shared/server.go` | `Server` struct with worker pool, HTTP lifecycle, graceful shutdown |
| `internal/shared/server_test.go` | Tests for Server (enqueue, lifecycle) |
| `internal/k8s/pipeline.go` | `ProcessAlert`, `PipelineDeps` |
| `internal/k8s/pipeline_test.go` | Tests for ProcessAlert |
| `internal/checkmk/pipeline.go` | `ProcessAlert`, `PipelineDeps` |
| `internal/checkmk/pipeline_test.go` | Tests for ProcessAlert |
| `.dockerignore` | Exclude .git, docs, .github from build context |
| `.golangci.yml` | Linter configuration |

### Modified files

| File | Changes |
|------|---------|
| `internal/shared/types.go` | Remove `ClaudeRequest`, `ClaudeMessage`, `ClaudeResponse` (use `ToolRequest`/`ToolMessage`/`ToolResponse` for all) |
| `internal/shared/claude.go` | Convert to `ClaudeClient` struct with `Analyze` and `RunToolLoop` methods |
| `internal/shared/claude_test.go` | Construct `ClaudeClient` with test HTTP client instead of swapping globals |
| `internal/shared/ntfy.go` | Add `HTTP` and `RetryDelays` fields to `NtfyPublisher`, remove globals |
| `internal/shared/ntfy_test.go` | Construct publisher with test HTTP client instead of swapping globals |
| `internal/shared/metrics.go` | Add histogram helpers, `/ready` handler support |
| `internal/shared/types_test.go` | Add `FormatForPrompt` test |
| `internal/k8s/context.go` | Remove global `promHTTPClient`, add `PrometheusClient` struct, parallelize `GetKubeContext` |
| `internal/k8s/context_test.go` | Update for `PrometheusClient` struct |
| `internal/checkmk/context.go` | Remove global `checkmkHTTPClient`, add `APIClient` struct |
| `internal/checkmk/context_test.go` | Update for `APIClient` struct |
| `internal/checkmk/ssh.go` | Add `SSHDialer` struct that caches parsed key |
| `internal/checkmk/ssh_test.go` | Update for `SSHDialer` |
| `internal/checkmk/agent.go` | Accept `Analyzer` + `SSHDialer` instead of `BaseConfig` |
| `internal/checkmk/agent_test.go` | Update for new signatures |
| `cmd/k8s-analyzer/main.go` | Slim to ~35 lines using `shared.Server` + `k8s.ProcessAlert` |
| `cmd/checkmk-analyzer/main.go` | Slim to ~40 lines using `shared.Server` + `checkmk.ProcessAlert` |
| `.github/workflows/build.yaml` | Add test + lint jobs gating builds |

---

## Task 1: CI test and lint jobs

**Files:**
- Modify: `.github/workflows/build.yaml`

- [ ] **Step 1: Add test and lint jobs, gate builds**

```yaml
---
name: Build Analyzer Images

on:
  push:
    branches: [main]
    paths:
      - "cmd/**"
      - "internal/**"
      - "Dockerfile"
      - "go.mod"
      - "go.sum"
      - ".github/workflows/build.yaml"
  workflow_dispatch:

permissions:
  contents: read
  packages: write

concurrency:
  group: ${{ github.workflow }}
  cancel-in-progress: false

env:
  REGISTRY: ghcr.io/${{ github.repository_owner }}

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
      - run: go vet ./...
      - run: go test -race -count=1 ./...

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
      - uses: golangci/golangci-lint-action@v7

  build-k8s:
    needs: [test, lint]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - name: Set tag
        id: tag
        run: echo "sha_short=$(git rev-parse --short HEAD)" >> "$GITHUB_OUTPUT"
      - uses: docker/setup-buildx-action@v4
      - uses: docker/login-action@v4
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v7
        with:
          context: .
          target: k8s-analyzer
          push: true
          tags: |
            ${{ env.REGISTRY }}/claude-alert-kubernetes-analyzer:${{ steps.tag.outputs.sha_short }}
            ${{ env.REGISTRY }}/claude-alert-kubernetes-analyzer:latest
          cache-from: type=gha
          cache-to: type=gha,mode=max

  build-checkmk:
    needs: [test, lint]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - name: Set tag
        id: tag
        run: echo "sha_short=$(git rev-parse --short HEAD)" >> "$GITHUB_OUTPUT"
      - uses: docker/setup-buildx-action@v4
      - uses: docker/login-action@v4
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v7
        with:
          context: .
          target: checkmk-analyzer
          push: true
          tags: |
            ${{ env.REGISTRY }}/claude-alert-checkmk-analyzer:${{ steps.tag.outputs.sha_short }}
            ${{ env.REGISTRY }}/claude-alert-checkmk-analyzer:latest
          cache-from: type=gha
          cache-to: type=gha,mode=max
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/build.yaml
git commit -m "ci: add test and lint jobs gating Docker builds"
```

---

## Task 2: Quick security and hygiene fixes

**Files:**
- Modify: `internal/k8s/context.go:45`
- Modify: `internal/k8s/context_test.go` (verify existing tests still pass)
- Create: `.dockerignore`

- [ ] **Step 1: Run tests to verify green baseline**

```bash
go test ./internal/k8s/ -v -count=1
```

Expected: all tests PASS.

- [ ] **Step 2: Bound Prometheus response body**

In `internal/k8s/context.go`, replace the unbounded `io.ReadAll` in `promqlQuery`:

```go
// Before (line 45):
body, err := io.ReadAll(resp.Body)

// After:
body, err := io.ReadAll(io.LimitReader(resp.Body, shared.MaxResponseBytes))
```

Add `"github.com/madic-creates/claude-alert-analyzer/internal/shared"` to imports if not already present (it is already imported).

- [ ] **Step 3: Run tests to verify still green**

```bash
go test ./internal/k8s/ -v -count=1
```

Expected: all tests PASS.

- [ ] **Step 4: Create `.dockerignore`**

```
.git
.github
docs
*.md
```

- [ ] **Step 5: Commit**

```bash
git add internal/k8s/context.go .dockerignore
git commit -m "security: bound Prometheus response body with LimitReader, add .dockerignore"
```

---

## Task 3: FormatForPrompt test and response type unification

**Files:**
- Modify: `internal/shared/types_test.go`
- Modify: `internal/shared/types.go`
- Modify: `internal/shared/claude.go`

- [ ] **Step 1: Write FormatForPrompt test**

Add to `internal/shared/types_test.go`:

```go
func TestFormatForPrompt(t *testing.T) {
	ac := AnalysisContext{
		Sections: []ContextSection{
			{Name: "Metrics", Content: "cpu=90%"},
			{Name: "Events", Content: "pod restarted"},
		},
	}
	got := ac.FormatForPrompt()
	want := "## Metrics\ncpu=90%\n\n## Events\npod restarted\n\n"
	if got != want {
		t.Errorf("FormatForPrompt() =\n%q\nwant:\n%q", got, want)
	}
}

func TestFormatForPrompt_Empty(t *testing.T) {
	ac := AnalysisContext{}
	got := ac.FormatForPrompt()
	if got != "" {
		t.Errorf("FormatForPrompt() = %q, want empty", got)
	}
}
```

- [ ] **Step 2: Run test to verify it passes**

```bash
go test ./internal/shared/ -run TestFormatForPrompt -v
```

Expected: PASS.

- [ ] **Step 3: Unify response types — remove ClaudeRequest, ClaudeMessage, ClaudeResponse**

In `internal/shared/types.go`, remove these three types (lines 52-63 and 129-143):

```go
// DELETE: ClaudeRequest (lines 52-58)
// DELETE: ClaudeMessage (lines 60-63)
// DELETE: ClaudeResponse (lines 129-143)
```

Keep all `Tool*` types as-is (`ToolRequest`, `ToolMessage`, `ToolResponse`, `ContentBlock`, `Tool`, etc.).

- [ ] **Step 4: Update AnalyzeWithClaude to use unified types**

In `internal/shared/claude.go`, update `AnalyzeWithClaude`:

```go
func AnalyzeWithClaude(ctx context.Context, cfg BaseConfig, systemPrompt, userPrompt string) (string, error) {
	reqBody := ToolRequest{
		Model:     cfg.ClaudeModel,
		MaxTokens: 2048,
		System:    systemPrompt,
		Messages:  []ToolMessage{{Role: "user", Content: userPrompt}},
	}

	respBody, err := sendRequest(ctx, cfg, reqBody)
	if err != nil {
		return "", err
	}

	var result ToolResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}

	if result.Error != nil {
		return "", fmt.Errorf("API error: %s: %s", result.Error.Type, result.Error.Message)
	}

	slog.Info("Claude analysis complete",
		"model", cfg.ClaudeModel,
		"inputTokens", result.Usage.InputTokens,
		"outputTokens", result.Usage.OutputTokens)

	return extractText(result.Content), nil
}
```

- [ ] **Step 5: Run all tests**

```bash
go test ./... -count=1
```

Expected: all PASS. The JSON wire format is unchanged — `ToolResponse` has the same fields as `ClaudeResponse` plus extras that are ignored for single-turn.

- [ ] **Step 6: Commit**

```bash
git add internal/shared/types.go internal/shared/types_test.go internal/shared/claude.go
git commit -m "refactor: unify Claude API types, remove ClaudeRequest/ClaudeMessage/ClaudeResponse"
```

---

## Task 4: Shared config helpers

**Files:**
- Create: `internal/shared/config.go`
- Create: `internal/shared/config_test.go`

- [ ] **Step 1: Write failing tests for config helpers**

Create `internal/shared/config_test.go`:

```go
package shared

import (
	"os"
	"testing"
)

func TestEnvOrDefault_Set(t *testing.T) {
	t.Setenv("TEST_KEY", "custom")
	if got := EnvOrDefault("TEST_KEY", "fallback"); got != "custom" {
		t.Errorf("got %q, want %q", got, "custom")
	}
}

func TestEnvOrDefault_Unset(t *testing.T) {
	os.Unsetenv("TEST_KEY_MISSING")
	if got := EnvOrDefault("TEST_KEY_MISSING", "fallback"); got != "fallback" {
		t.Errorf("got %q, want %q", got, "fallback")
	}
}

func TestParseIntEnv_Valid(t *testing.T) {
	t.Setenv("TEST_INT", "42")
	got, err := ParseIntEnv("TEST_INT", "10", 0, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 42 {
		t.Errorf("got %d, want 42", got)
	}
}

func TestParseIntEnv_Default(t *testing.T) {
	os.Unsetenv("TEST_INT_MISSING")
	got, err := ParseIntEnv("TEST_INT_MISSING", "10", 0, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 10 {
		t.Errorf("got %d, want 10", got)
	}
}

func TestParseIntEnv_InvalidString(t *testing.T) {
	t.Setenv("TEST_INT", "abc")
	_, err := ParseIntEnv("TEST_INT", "10", 0, 100)
	if err == nil {
		t.Fatal("expected error for non-numeric value")
	}
}

func TestParseIntEnv_OutOfRange(t *testing.T) {
	t.Setenv("TEST_INT", "200")
	_, err := ParseIntEnv("TEST_INT", "10", 0, 100)
	if err == nil {
		t.Fatal("expected error for out-of-range value")
	}
}

func TestRequireEnv_Set(t *testing.T) {
	t.Setenv("TEST_REQ", "value")
	got, err := RequireEnv("TEST_REQ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "value" {
		t.Errorf("got %q, want %q", got, "value")
	}
}

func TestRequireEnv_Unset(t *testing.T) {
	os.Unsetenv("TEST_REQ_MISSING")
	_, err := RequireEnv("TEST_REQ_MISSING")
	if err == nil {
		t.Fatal("expected error for unset env var")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/shared/ -run "TestEnvOrDefault|TestParseIntEnv|TestRequireEnv" -v
```

Expected: FAIL (functions not defined).

- [ ] **Step 3: Implement config helpers**

Create `internal/shared/config.go`:

```go
package shared

import (
	"fmt"
	"os"
	"strconv"
)

// EnvOrDefault returns the value of the environment variable key,
// or fallback if the variable is not set or empty.
func EnvOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ParseIntEnv reads an integer environment variable with range validation.
// Returns an error if the value is not a valid integer or falls outside [min, max].
func ParseIntEnv(key, fallback string, min, max int) (int, error) {
	raw := EnvOrDefault(key, fallback)
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s=%q: not a valid integer", key, raw)
	}
	if v < min || v > max {
		return 0, fmt.Errorf("%s=%d: must be between %d and %d", key, v, min, max)
	}
	return v, nil
}

// RequireEnv returns the value of the environment variable key,
// or an error if it is not set or empty.
func RequireEnv(key string) (string, error) {
	v := os.Getenv(key)
	if v == "" {
		return "", fmt.Errorf("%s is required but not set", key)
	}
	return v, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/shared/ -run "TestEnvOrDefault|TestParseIntEnv|TestRequireEnv" -v
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/shared/config.go internal/shared/config_test.go
git commit -m "feat: add shared config helpers (EnvOrDefault, ParseIntEnv, RequireEnv)"
```

---

## Task 5: Analyzer interface and ClaudeClient struct

**Files:**
- Create: `internal/shared/interfaces.go`
- Modify: `internal/shared/claude.go`
- Modify: `internal/shared/claude_test.go`

- [ ] **Step 1: Run existing Claude tests to verify green baseline**

```bash
go test ./internal/shared/ -run TestAnalyze -v -count=1
```

Expected: all PASS.

- [ ] **Step 2: Create interfaces**

Create `internal/shared/interfaces.go`:

```go
package shared

import (
	"context"
	"encoding/json"
)

// Analyzer performs single-turn Claude analysis.
type Analyzer interface {
	Analyze(ctx context.Context, systemPrompt, userPrompt string) (string, error)
}

// ToolLoopRunner performs multi-turn Claude tool-use conversations.
type ToolLoopRunner interface {
	RunToolLoop(ctx context.Context, systemPrompt, userPrompt string,
		tools []Tool, maxRounds int,
		handleTool func(name string, input json.RawMessage) (string, error),
	) (string, error)
}
```

- [ ] **Step 3: Convert claude.go to ClaudeClient struct**

Replace the contents of `internal/shared/claude.go` with:

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

// MaxResponseBytes bounds the amount of data read from an API response body
// to prevent a malicious or buggy upstream from exhausting memory.
const MaxResponseBytes = 2 * 1024 * 1024 // 2 MiB

// ClaudeClient holds the HTTP client and credentials for Claude API calls.
type ClaudeClient struct {
	HTTP    *http.Client
	BaseURL string
	APIKey  string
	Model   string
}

// NewClaudeClient creates a ClaudeClient with a default 120s timeout HTTP client.
func NewClaudeClient(cfg BaseConfig) *ClaudeClient {
	return &ClaudeClient{
		HTTP:    &http.Client{Timeout: 120 * time.Second},
		BaseURL: cfg.APIBaseURL,
		APIKey:  cfg.APIKey,
		Model:   cfg.ClaudeModel,
	}
}

func (c *ClaudeClient) sendRequest(ctx context.Context, body any) ([]byte, error) {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	if strings.Contains(c.BaseURL, "anthropic.com") {
		req.Header.Set("x-api-key", c.APIKey)
		req.Header.Set("anthropic-version", anthropicVersion)
	} else {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned %d: %s", resp.StatusCode, Truncate(string(respBody), 300))
	}

	return respBody, nil
}

// Analyze sends a single-turn analysis request. Implements Analyzer.
func (c *ClaudeClient) Analyze(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	reqBody := ToolRequest{
		Model:     c.Model,
		MaxTokens: 2048,
		System:    systemPrompt,
		Messages:  []ToolMessage{{Role: "user", Content: userPrompt}},
	}

	respBody, err := c.sendRequest(ctx, reqBody)
	if err != nil {
		return "", err
	}

	var result ToolResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}

	if result.Error != nil {
		return "", fmt.Errorf("API error: %s: %s", result.Error.Type, result.Error.Message)
	}

	slog.Info("Claude analysis complete",
		"model", c.Model,
		"inputTokens", result.Usage.InputTokens,
		"outputTokens", result.Usage.OutputTokens)

	return extractText(result.Content), nil
}

// RunToolLoop runs a multi-turn Claude conversation with tool use.
// handleTool is called for each tool_use block. After maxRounds of tool calls,
// a final request forces Claude to produce a text response. Implements ToolLoopRunner.
func (c *ClaudeClient) RunToolLoop(
	ctx context.Context,
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
			Model:     c.Model,
			MaxTokens: 4096,
			System:    systemPrompt,
			Tools:     tools,
			Messages:  messages,
		}

		respBody, err := c.sendRequest(ctx, reqBody)
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

		messages = append(messages, ToolMessage{Role: "assistant", Content: resp.Content})

		if resp.StopReason == "end_turn" {
			slog.Info("tool loop complete",
				"rounds", round+1,
				"totalInputTokens", totalInput,
				"totalOutputTokens", totalOutput)
			return extractText(resp.Content), nil
		}

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

	slog.Info("tool loop max rounds reached, requesting summary", "maxRounds", maxRounds)

	messages = append(messages, ToolMessage{
		Role:    "user",
		Content: "You have reached the maximum number of diagnostic rounds. Do NOT call any more tools. Provide your final analysis now based on all information gathered so far. Start directly with the analysis — no preamble or meta-commentary.",
	})

	reqBody := ToolRequest{
		Model:     c.Model,
		MaxTokens: 4096,
		System:    systemPrompt,
		Tools:     tools,
		Messages:  messages,
	}

	respBody, err := c.sendRequest(ctx, reqBody)
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

	analysis := extractText(resp.Content)

	slog.Info("tool loop complete (forced summary)",
		"totalRounds", maxRounds,
		"totalInputTokens", totalInput,
		"totalOutputTokens", totalOutput,
		"analysisLen", len(analysis))

	if len(analysis) == 0 {
		slog.Warn("forced summary produced empty analysis", "contentBlocks", len(resp.Content))
	}

	return analysis, nil
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

- [ ] **Step 4: Update claude_test.go**

All tests that used the global `claudeHTTPClient` now construct a `ClaudeClient` directly. The pattern for every test changes from:

```go
// OLD:
origClient := claudeHTTPClient
claudeHTTPClient = ts.Client()
defer func() { claudeHTTPClient = origClient }()
cfg := BaseConfig{APIBaseURL: ts.URL, APIKey: "test", ClaudeModel: "test"}
result, err := AnalyzeWithClaude(ctx, cfg, system, user)

// NEW:
client := &ClaudeClient{HTTP: ts.Client(), BaseURL: ts.URL, APIKey: "test", Model: "test"}
result, err := client.Analyze(ctx, system, user)
```

For `RunToolLoop` tests:

```go
// OLD:
cfg := BaseConfig{APIBaseURL: ts.URL, APIKey: "test", ClaudeModel: "test"}
result, err := RunToolLoop(ctx, cfg, system, user, tools, maxRounds, handler)

// NEW:
client := &ClaudeClient{HTTP: ts.Client(), BaseURL: ts.URL, APIKey: "test", Model: "test"}
result, err := client.RunToolLoop(ctx, system, user, tools, maxRounds, handler)
```

Apply this pattern to every test function in `claude_test.go`. Remove the `claudeHTTPClient` global references entirely.

- [ ] **Step 5: Update callers in cmd/ and internal/checkmk/**

In `cmd/k8s-analyzer/main.go`, change `processAlert` to use a `*shared.ClaudeClient`:

```go
// Replace:
analysis, err := shared.AnalyzeWithClaude(ctx, baseCfg, systemPrompt, userPrompt)

// With (claudeClient constructed in main()):
analysis, err := claudeClient.Analyze(ctx, systemPrompt, userPrompt)
```

In `cmd/checkmk-analyzer/main.go`, same pattern for the non-SSH path, plus pass `claudeClient` to `RunAgenticDiagnostics`.

In `internal/checkmk/agent.go`, update `RunAgenticDiagnostics` signature:

```go
// Before:
func RunAgenticDiagnostics(ctx context.Context, cfg Config, claudeCfg shared.BaseConfig, hostname string, alertContext string, maxRounds int) (string, error) {

// After:
func RunAgenticDiagnostics(ctx context.Context, cfg Config, client shared.ToolLoopRunner, hostname string, alertContext string, maxRounds int) (string, error) {
```

And replace `shared.RunToolLoop(ctx, claudeCfg, ...)` with `client.RunToolLoop(ctx, ...)`.

Update `agent_test.go` accordingly — construct a `ClaudeClient` with a test HTTP server instead of using globals.

- [ ] **Step 6: Run all tests**

```bash
go test ./... -count=1
```

Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/shared/interfaces.go internal/shared/claude.go internal/shared/claude_test.go internal/checkmk/agent.go internal/checkmk/agent_test.go cmd/k8s-analyzer/main.go cmd/checkmk-analyzer/main.go
git commit -m "refactor: replace global claudeHTTPClient with ClaudeClient struct, add Analyzer/ToolLoopRunner interfaces"
```

---

## Task 6: NtfyPublisher dependency injection

**Files:**
- Modify: `internal/shared/ntfy.go`
- Modify: `internal/shared/ntfy_test.go`

- [ ] **Step 1: Run existing ntfy tests to verify green baseline**

```bash
go test ./internal/shared/ -run TestNtfy -v -count=1
```

Expected: all PASS.

- [ ] **Step 2: Add HTTP and RetryDelays fields, remove globals**

In `internal/shared/ntfy.go`:

```go
package shared

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// DefaultNtfyRetryDelays is the default retry schedule for ntfy publishing.
var DefaultNtfyRetryDelays = []time.Duration{2 * time.Second, 5 * time.Second}

// NtfyPublisher sends notifications to an ntfy server.
type NtfyPublisher struct {
	HTTP        *http.Client
	URL         string
	Topic       string
	Token       string
	RetryDelays []time.Duration
}

// NewNtfyPublisher creates a publisher with default HTTP client and retry delays.
func NewNtfyPublisher(url, topic, token string) *NtfyPublisher {
	return &NtfyPublisher{
		HTTP:        &http.Client{Timeout: 10 * time.Second},
		URL:         url,
		Topic:       topic,
		Token:       token,
		RetryDelays: DefaultNtfyRetryDelays,
	}
}

func (n *NtfyPublisher) Name() string { return "ntfy" }

const maxNtfyBodyBytes = 4096

func (n *NtfyPublisher) Publish(ctx context.Context, title, priority, body string) error {
	body = Truncate(body, maxNtfyBodyBytes)
	ntfyURL := fmt.Sprintf("%s/%s", n.URL, n.Topic)

	retryDelays := n.RetryDelays
	if retryDelays == nil {
		retryDelays = DefaultNtfyRetryDelays
	}

	var lastErr error
	for attempt := 0; attempt <= len(retryDelays); attempt++ {
		if attempt > 0 {
			delay := retryDelays[attempt-1]
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
			slog.Warn("retrying ntfy publish", "attempt", attempt+1, "after", delay)
		}

		req, err := http.NewRequestWithContext(ctx, "POST", ntfyURL, strings.NewReader(body))
		if err != nil {
			return fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Title", title)
		req.Header.Set("Priority", priority)
		req.Header.Set("Tags", "robot,mag")
		req.Header.Set("Markdown", "yes")
		if n.Token != "" {
			req.Header.Set("Authorization", "Bearer "+n.Token)
		}

		resp, err := n.HTTP.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("publish: %w", err)
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("ntfy returned %d", resp.StatusCode)
			continue
		}
		if resp.StatusCode >= 300 {
			return fmt.Errorf("ntfy returned %d", resp.StatusCode)
		}
		return nil
	}
	return lastErr
}

// PublishAll sends to all publishers, logging errors. Returns the first error encountered.
func PublishAll(ctx context.Context, publishers []Publisher, title, priority, body string) error {
	var firstErr error
	for _, p := range publishers {
		if err := p.Publish(ctx, title, priority, body); err != nil {
			slog.Error("publish failed", "publisher", p.Name(), "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}
```

- [ ] **Step 3: Update ntfy_test.go**

Change all tests from swapping globals to constructing `NtfyPublisher` with test clients:

```go
// OLD:
origClient := ntfyHTTPClient
ntfyHTTPClient = ts.Client()
defer func() { ntfyHTTPClient = origClient }()
origDelays := ntfyRetryDelays
ntfyRetryDelays = []time.Duration{1 * time.Millisecond}
defer func() { ntfyRetryDelays = origDelays }()
pub := &NtfyPublisher{URL: ts.URL, Topic: "test"}

// NEW:
pub := &NtfyPublisher{
    HTTP:        ts.Client(),
    URL:         ts.URL,
    Topic:       "test",
    RetryDelays: []time.Duration{1 * time.Millisecond},
}
```

Apply this pattern to every test in `ntfy_test.go`.

- [ ] **Step 4: Update callers in main.go files**

In both `cmd/*/main.go`, replace the `buildPublishers` function to use `NewNtfyPublisher`:

```go
// This will be fully replaced in Task 10 (server scaffold).
// For now, update buildPublishers to use NewNtfyPublisher:
func buildPublishers() []shared.Publisher {
    return []shared.Publisher{
        shared.NewNtfyPublisher(
            envOrDefault("NTFY_PUBLISH_URL", "https://ntfy.example.com"),
            envOrDefault("NTFY_PUBLISH_TOPIC", "kubernetes-analysis"),
            os.Getenv("NTFY_PUBLISH_TOKEN"),
        ),
    }
}
```

- [ ] **Step 5: Run all tests**

```bash
go test ./... -count=1
```

Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/shared/ntfy.go internal/shared/ntfy_test.go cmd/k8s-analyzer/main.go cmd/checkmk-analyzer/main.go
git commit -m "refactor: inject HTTP client and retry delays into NtfyPublisher, remove globals"
```

---

## Task 7: K8s dependency injection and context parallelization

**Files:**
- Modify: `internal/k8s/context.go`
- Modify: `internal/k8s/context_test.go`

- [ ] **Step 1: Run existing tests to verify green baseline**

```bash
go test ./internal/k8s/ -v -count=1
```

Expected: all PASS.

- [ ] **Step 2: Replace global promHTTPClient with PrometheusClient struct**

In `internal/k8s/context.go`, replace the global client and free `promqlQuery` function:

```go
// Remove:
var promHTTPClient = &http.Client{Timeout: 10 * time.Second}

// Add:
type PrometheusClient struct {
	HTTP *http.Client
	URL  string
}

func NewPrometheusClient(url string) *PrometheusClient {
	return &PrometheusClient{
		HTTP: &http.Client{Timeout: 10 * time.Second},
		URL:  url,
	}
}
```

Convert `promqlQuery` to a method:

```go
// Before:
func promqlQuery(ctx context.Context, prometheusURL, query string) string {
    u := fmt.Sprintf("%s/api/v1/query?query=%s", prometheusURL, ...)
    ...
    resp, err := promHTTPClient.Do(req)

// After:
func (p *PrometheusClient) query(ctx context.Context, queryStr string) string {
    u := fmt.Sprintf("%s/api/v1/query?query=%s", p.URL, url.QueryEscape(queryStr))
    ...
    resp, err := p.HTTP.Do(req)
    ...
    body, err := io.ReadAll(io.LimitReader(resp.Body, shared.MaxResponseBytes))
```

Convert `GetPrometheusMetrics` to a method:

```go
func (p *PrometheusClient) GetMetrics(ctx context.Context, alert Alert) string {
    // Same logic, using p.query instead of promqlQuery
}
```

- [ ] **Step 3: Parallelize GetKubeContext**

Replace the sequential events/pods/logs calls with goroutines:

```go
func GetKubeContext(ctx context.Context, clientset kubernetes.Interface, alert Alert, cfg Config) (events, pods, logs string) {
	namespace := alert.Labels["namespace"]
	if namespace == "" {
		return "(no namespace in alert)", "(no namespace)", "(no namespace)"
	}

	type result struct {
		events, pods, logs string
	}

	var wg sync.WaitGroup
	var eventsResult, podsResult, logsResult string

	wg.Add(3)
	go func() {
		defer wg.Done()
		eventsResult = getEvents(ctx, clientset, namespace)
	}()
	go func() {
		defer wg.Done()
		podsResult = getPodStatus(ctx, clientset, namespace)
	}()
	go func() {
		defer wg.Done()
		logsResult = getPodLogs(ctx, clientset, namespace, alert, cfg)
	}()
	wg.Wait()

	return eventsResult, podsResult, logsResult
}
```

Extract the three inner blocks into private helper functions `getEvents`, `getPodStatus`, `getPodLogs` (each containing the existing logic from the current `GetKubeContext`). Add `"sync"` to imports.

- [ ] **Step 4: Update GatherContext signature**

```go
// Before:
func GatherContext(ctx context.Context, clientset kubernetes.Interface, prometheusURL string, alert Alert, cfg Config) shared.AnalysisContext {

// After:
func GatherContext(ctx context.Context, prom *PrometheusClient, clientset kubernetes.Interface, alert Alert, cfg Config) shared.AnalysisContext {
```

Replace `GetPrometheusMetrics(ctx, prometheusURL, alert)` with `prom.GetMetrics(ctx, alert)`.

- [ ] **Step 5: Update context_test.go**

Tests that used `httptest.NewServer` for Prometheus and swapped the global need updating:

```go
// OLD:
origClient := promHTTPClient
promHTTPClient = ts.Client()
defer func() { promHTTPClient = origClient }()
result := promqlQuery(ctx, ts.URL, "up")

// NEW:
prom := &PrometheusClient{HTTP: ts.Client(), URL: ts.URL}
result := prom.query(ctx, "up")
```

Update all `GatherContext` test calls to pass a `*PrometheusClient`.

- [ ] **Step 6: Update k8s main.go caller**

```go
// In processAlert, change:
actx := k8s.GatherContext(ctx, clientset, cfg.PrometheusURL, k8sAlert, cfg)

// To:
actx := k8s.GatherContext(ctx, promClient, clientset, k8sAlert, cfg)
```

Where `promClient` is constructed in `main()`:
```go
promClient := k8s.NewPrometheusClient(cfg.PrometheusURL)
```

- [ ] **Step 7: Run all tests**

```bash
go test ./... -count=1
```

Expected: all PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/k8s/context.go internal/k8s/context_test.go cmd/k8s-analyzer/main.go
git commit -m "refactor: PrometheusClient struct, parallelize K8s context gathering"
```

---

## Task 8: CheckMK dependency injection (APIClient, SSHDialer)

**Files:**
- Modify: `internal/checkmk/context.go`
- Modify: `internal/checkmk/context_test.go`
- Modify: `internal/checkmk/ssh.go`
- Modify: `internal/checkmk/ssh_test.go`
- Modify: `internal/checkmk/agent.go`
- Modify: `internal/checkmk/agent_test.go`

- [ ] **Step 1: Run existing tests to verify green baseline**

```bash
go test ./internal/checkmk/ -v -count=1
```

Expected: all PASS.

- [ ] **Step 2: Create APIClient struct, replace global checkmkHTTPClient**

In `internal/checkmk/context.go`:

```go
// Remove:
var checkmkHTTPClient = &http.Client{Timeout: 10 * time.Second}

// Add:
type APIClient struct {
	HTTP   *http.Client
	URL    string
	User   string
	Secret string
}

func NewAPIClient(cfg Config) *APIClient {
	return &APIClient{
		HTTP:   &http.Client{Timeout: 10 * time.Second},
		URL:    cfg.CheckMKAPIURL,
		User:   cfg.CheckMKAPIUser,
		Secret: cfg.CheckMKAPISecret,
	}
}
```

Convert `ValidateAndDescribeHost` and `getHostServices` to methods on `APIClient`:

```go
// Before:
func ValidateAndDescribeHost(ctx context.Context, cfg Config, hostname, hostAddress string) (*HostInfo, error) {
    req.Header.Set("Authorization", fmt.Sprintf("Bearer %s %s", cfg.CheckMKAPIUser, cfg.CheckMKAPISecret))
    resp, err := checkmkHTTPClient.Do(req)

// After:
func (c *APIClient) ValidateAndDescribeHost(ctx context.Context, hostname, hostAddress string) (*HostInfo, error) {
    url := fmt.Sprintf("%sobjects/host_config/%s", c.URL, hostname)
    req.Header.Set("Authorization", fmt.Sprintf("Bearer %s %s", c.User, c.Secret))
    resp, err := c.HTTP.Do(req)
```

Same pattern for `getHostServices` → `(c *APIClient) GetHostServices`.

Update `GatherContext` to accept `*APIClient`:

```go
func GatherContext(ctx context.Context, apiClient *APIClient, alert shared.AlertPayload, hostInfo *HostInfo) shared.AnalysisContext {
    // Replace getHostServices(ctx, cfg, hostname) with:
    apiClient.GetHostServices(ctx, hostname)
}
```

- [ ] **Step 3: Create SSHDialer struct with cached key**

In `internal/checkmk/ssh.go`:

```go
// SSHDialer caches the parsed SSH key and known_hosts callback.
type SSHDialer struct {
	signer          ssh.Signer
	hostKeyCallback ssh.HostKeyCallback
	user            string
}

// NewSSHDialer parses the SSH key and known_hosts file once.
func NewSSHDialer(cfg Config) (*SSHDialer, error) {
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

	return &SSHDialer{
		signer:          signer,
		hostKeyCallback: hostKeyCallback,
		user:            cfg.SSHUser,
	}, nil
}

func (d *SSHDialer) Dial(hostAddress string) (*ssh.Client, error) {
	sshCfg := &ssh.ClientConfig{
		User:            d.user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(d.signer)},
		HostKeyCallback: d.hostKeyCallback,
		Timeout:         10 * time.Second,
	}

	addr := net.JoinHostPort(hostAddress, "22")
	client, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		return nil, fmt.Errorf("SSH dial %s: %w", addr, err)
	}
	return client, nil
}
```

Remove the old `dialSSH` free function.

- [ ] **Step 4: Update RunAgenticDiagnostics to use SSHDialer**

In `internal/checkmk/agent.go`:

```go
// Before:
func RunAgenticDiagnostics(ctx context.Context, cfg Config, claudeCfg shared.BaseConfig, hostname string, alertContext string, maxRounds int) (string, error) {
    ...
    client, err := dialSSH(cfg, hostname)

// After:
func RunAgenticDiagnostics(ctx context.Context, cfg Config, analyzer shared.ToolLoopRunner, dialer *SSHDialer, hostname string, alertContext string, maxRounds int) (string, error) {
    ...
    client, err := dialer.Dial(hostname)
```

And replace the `shared.RunToolLoop(ctx, claudeCfg, ...)` call with `analyzer.RunToolLoop(ctx, ...)`.

- [ ] **Step 5: Update context_test.go and agent_test.go**

In `context_test.go`, replace global client swaps with `APIClient` construction:

```go
apiClient := &APIClient{HTTP: ts.Client(), URL: ts.URL + "/", User: "test", Secret: "test"}
```

In `agent_test.go`, construct a `ClaudeClient` (for `ToolLoopRunner`) with test HTTP server and pass a `SSHDialer` or skip SSH tests that require real key files.

- [ ] **Step 6: Update checkmk main.go caller**

```go
// In main():
apiClient := checkmk.NewAPIClient(cfg)

// For SSH:
var sshDialer *checkmk.SSHDialer
if cfg.SSHEnabled {
    var err error
    sshDialer, err = checkmk.NewSSHDialer(cfg)
    if err != nil {
        slog.Error("SSH dialer init failed", "error", err)
        os.Exit(1)
    }
}

// In processAlert:
hostInfo, validationErr := apiClient.ValidateAndDescribeHost(ctx, hostname, hostAddress)
actx := checkmk.GatherContext(ctx, apiClient, alert, hostInfo)
analysis, err = checkmk.RunAgenticDiagnostics(ctx, cfg, claudeClient, sshDialer, hostAddress, alertContext, cfg.MaxAgentRounds)
```

- [ ] **Step 7: Run all tests**

```bash
go test ./... -count=1
```

Expected: all PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/checkmk/context.go internal/checkmk/context_test.go internal/checkmk/ssh.go internal/checkmk/ssh_test.go internal/checkmk/agent.go internal/checkmk/agent_test.go cmd/checkmk-analyzer/main.go
git commit -m "refactor: APIClient and SSHDialer structs, remove global HTTP clients in checkmk"
```

---

## Task 9: Server scaffold

**Files:**
- Create: `internal/shared/server.go`
- Create: `internal/shared/server_test.go`

- [ ] **Step 1: Write failing test for Server**

Create `internal/shared/server_test.go`:

```go
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
		WorkerCount:  0, // no workers, so queue fills up
		QueueSize:    1,
		DrainTimeout: 5 * time.Second,
	}, metrics, func(ctx context.Context, alert AlertPayload) {})

	srv.Enqueue(AlertPayload{Fingerprint: "a"}) // fills queue
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/shared/ -run "TestServer" -v
```

Expected: FAIL (types not defined).

- [ ] **Step 3: Implement Server**

Create `internal/shared/server.go`:

```go
package shared

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// ServerConfig holds settings for the shared HTTP server and worker pool.
type ServerConfig struct {
	Port         string
	WorkerCount  int
	QueueSize    int
	DrainTimeout time.Duration
}

// Server manages a webhook-driven worker pool with graceful shutdown.
type Server struct {
	cfg     ServerConfig
	metrics *AlertMetrics
	process func(ctx context.Context, alert AlertPayload)
	queue   chan AlertPayload
}

// NewServer creates a Server. Call Enqueue to add alerts, Run to start.
func NewServer(cfg ServerConfig, metrics *AlertMetrics, process func(ctx context.Context, alert AlertPayload)) *Server {
	return &Server{
		cfg:     cfg,
		metrics: metrics,
		process: process,
		queue:   make(chan AlertPayload, cfg.QueueSize),
	}
}

// Enqueue attempts to place an alert on the work queue.
// Returns false if the queue is full.
func (s *Server) Enqueue(alert AlertPayload) bool {
	select {
	case s.queue <- alert:
		s.metrics.AlertsQueued.Add(1)
		return true
	default:
		s.metrics.AlertsQueueFull.Add(1)
		return false
	}
}

// BuildMux returns an http.ServeMux with /health, /metrics, and POST /webhook.
// The webhookHandler is wrapped to increment WebhooksReceived.
func (s *Server) BuildMux(webhookHandler http.HandlerFunc) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})
	mux.HandleFunc("GET /metrics", s.metrics.MetricsHandler())
	mux.HandleFunc("POST /webhook", func(w http.ResponseWriter, r *http.Request) {
		s.metrics.WebhooksReceived.Add(1)
		webhookHandler(w, r)
	})
	return mux
}

// Run starts workers, serves HTTP, and blocks until SIGINT/SIGTERM triggers
// graceful shutdown. This function does not return until shutdown is complete.
func (s *Server) Run(webhookHandler http.HandlerFunc) {
	workerCtx, workerCancel := context.WithCancel(context.Background())
	defer workerCancel()

	var wg sync.WaitGroup
	for range s.cfg.WorkerCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for alert := range s.queue {
				s.process(workerCtx, alert)
			}
		}()
	}

	mux := s.BuildMux(webhookHandler)

	server := &http.Server{
		Addr:              ":" + s.cfg.Port,
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			slog.Error("server failed", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	server.Shutdown(shutdownCtx)
	close(s.queue)

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		slog.Info("all workers finished")
	case <-time.After(s.cfg.DrainTimeout):
		slog.Warn("worker drain timeout, cancelling")
		workerCancel()
		wg.Wait()
	}
	slog.Info("shutdown complete")
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/shared/ -run "TestServer" -v -count=1
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/shared/server.go internal/shared/server_test.go
git commit -m "feat: add shared Server scaffold with worker pool and graceful shutdown"
```

---

## Task 10: K8s pipeline extraction and slim main.go

**Files:**
- Create: `internal/k8s/pipeline.go`
- Create: `internal/k8s/pipeline_test.go`
- Modify: `cmd/k8s-analyzer/main.go`

- [ ] **Step 1: Write tests for ProcessAlert**

Create `internal/k8s/pipeline_test.go`:

```go
package k8s

import (
	"context"
	"testing"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
)

type mockAnalyzer struct {
	result string
	err    error
}

func (m *mockAnalyzer) Analyze(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	return m.result, m.err
}

type mockPublisher struct {
	published []string
	err       error
}

func (m *mockPublisher) Publish(ctx context.Context, title, priority, body string) error {
	m.published = append(m.published, body)
	return m.err
}

func (m *mockPublisher) Name() string { return "mock" }

func TestProcessAlert_Success(t *testing.T) {
	pub := &mockPublisher{}
	cooldown := shared.NewCooldownManager()
	metrics := new(shared.AlertMetrics)

	deps := PipelineDeps{
		Analyzer:     &mockAnalyzer{result: "root cause: OOM"},
		Publishers:   []shared.Publisher{pub},
		Cooldown:     cooldown,
		Metrics:      metrics,
		SystemPrompt: "test prompt",
		GatherContext: func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext {
			return shared.AnalysisContext{
				Sections: []shared.ContextSection{{Name: "Test", Content: "data"}},
			}
		},
	}

	alert := shared.AlertPayload{
		Fingerprint: "abc",
		Title:       "HighCPU",
		Severity:    "critical",
		Source:      "k8s",
		Fields:      map[string]string{"status": "firing", "label:namespace": "monitoring"},
	}

	ProcessAlert(context.Background(), deps, alert)

	if metrics.AlertsProcessed.Load() != 1 {
		t.Errorf("AlertsProcessed = %d, want 1", metrics.AlertsProcessed.Load())
	}
	if len(pub.published) != 1 {
		t.Fatalf("published %d, want 1", len(pub.published))
	}
	if pub.published[0] != "root cause: OOM" {
		t.Errorf("published body = %q", pub.published[0])
	}
}

func TestProcessAlert_AnalysisFails(t *testing.T) {
	pub := &mockPublisher{}
	cooldown := shared.NewCooldownManager()
	metrics := new(shared.AlertMetrics)

	deps := PipelineDeps{
		Analyzer:     &mockAnalyzer{err: context.DeadlineExceeded},
		Publishers:   []shared.Publisher{pub},
		Cooldown:     cooldown,
		Metrics:      metrics,
		SystemPrompt: "test",
		GatherContext: func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext {
			return shared.AnalysisContext{}
		},
	}

	alert := shared.AlertPayload{Fingerprint: "abc", Title: "Test", Severity: "warning", Fields: map[string]string{}}
	ProcessAlert(context.Background(), deps, alert)

	if metrics.AlertsFailed.Load() != 1 {
		t.Errorf("AlertsFailed = %d, want 1", metrics.AlertsFailed.Load())
	}
	// Cooldown should be cleared on failure
	if !cooldown.CheckAndSet("abc", 300*1e9) {
		t.Error("cooldown not cleared after failure")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/k8s/ -run TestProcessAlert -v
```

Expected: FAIL (ProcessAlert not defined).

- [ ] **Step 3: Implement k8s pipeline**

Create `internal/k8s/pipeline.go`:

```go
package k8s

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
)

// PipelineDeps holds all dependencies for alert processing.
type PipelineDeps struct {
	Analyzer      shared.Analyzer
	Publishers    []shared.Publisher
	Cooldown      *shared.CooldownManager
	Metrics       *shared.AlertMetrics
	SystemPrompt  string
	GatherContext func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext
}

// ProcessAlert gathers context, analyzes via Claude, and publishes results.
func ProcessAlert(ctx context.Context, deps PipelineDeps, alert shared.AlertPayload) {
	alertname := alert.Title
	namespace := alert.Fields["label:namespace"]
	slog.Info("processing alert", "alertname", alertname, "namespace", namespace)

	actx := deps.GatherContext(ctx, alert)
	userPrompt := fmt.Sprintf("## Alert: %s\n- Status: %s\n- Severity: %s\n- Namespace: %s\n\n%s",
		alertname, alert.Fields["status"], alert.Severity, namespace, actx.FormatForPrompt())

	analysis, err := deps.Analyzer.Analyze(ctx, deps.SystemPrompt, userPrompt)
	if err != nil {
		slog.Error("analysis failed", "alertname", alertname, "error", err)
		_ = shared.PublishAll(ctx, deps.Publishers,
			fmt.Sprintf("Analysis FAILED: %s", alertname), "5",
			fmt.Sprintf("**Analysis failed** for %s: %v\n\nManual investigation needed.", alertname, err))
		deps.Cooldown.Clear(alert.Fingerprint)
		deps.Metrics.AlertsFailed.Add(1)
		return
	}

	title := fmt.Sprintf("Analysis: %s", alertname)
	if namespace != "" {
		title = fmt.Sprintf("Analysis: %s (%s)", alertname, namespace)
	}

	priorityMap := map[string]string{"critical": "5", "warning": "4", "info": "2"}
	priority := priorityMap[alert.Severity]
	if priority == "" {
		priority = "3"
	}

	if err := shared.PublishAll(ctx, deps.Publishers, title, priority, analysis); err != nil {
		deps.Cooldown.Clear(alert.Fingerprint)
		deps.Metrics.AlertsFailed.Add(1)
		return
	}

	deps.Metrics.AlertsProcessed.Add(1)
	slog.Info("analysis complete", "alertname", alertname)
}
```

- [ ] **Step 4: Run pipeline tests**

```bash
go test ./internal/k8s/ -run TestProcessAlert -v -count=1
```

Expected: all PASS.

- [ ] **Step 5: Slim down k8s main.go**

Replace `cmd/k8s-analyzer/main.go` entirely:

```go
package main

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/madic-creates/claude-alert-analyzer/internal/k8s"
	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const systemPrompt = `You are a Kubernetes SRE analyst for a k3s home cluster with Prometheus, Grafana, Longhorn storage, Traefik ingress, and Cilium CNI.

Analyze the provided alert with its cluster context and produce a concise root-cause analysis:
1. Identify the most likely root cause
2. Assess severity and blast radius
3. Suggest concrete remediation steps (kubectl commands, config changes)
4. Note correlations with other active alerts

Keep response under 500 words. Use markdown for formatting (headings, bold, lists, code blocks) but never use markdown tables. Use bullet lists instead of tables. Reference actual metric values and pod names.
Start directly with the analysis — no preamble, meta-commentary, or introductory sentences like "I have enough data" or "Let me analyze this".`

func loadConfig() k8s.Config {
	cooldown, err := shared.ParseIntEnv("COOLDOWN_SECONDS", "300", 0, 86400)
	if err != nil {
		slog.Error("invalid config", "error", err)
		os.Exit(1)
	}
	maxLogBytes, err := shared.ParseIntEnv("MAX_LOG_BYTES", "2048", 256, 1048576)
	if err != nil {
		slog.Error("invalid config", "error", err)
		os.Exit(1)
	}

	allowedNS := shared.EnvOrDefault("ALLOWED_NAMESPACES", "monitoring,databases,media")
	var nsList []string
	for _, ns := range strings.Split(allowedNS, ",") {
		ns = strings.TrimSpace(ns)
		if ns != "" {
			nsList = append(nsList, ns)
		}
	}

	webhookSecret, err := shared.RequireEnv("WEBHOOK_SECRET")
	if err != nil {
		slog.Error("config error", "error", err)
		os.Exit(1)
	}
	apiKey, err := shared.RequireEnv("API_KEY")
	if err != nil {
		slog.Error("config error", "error", err)
		os.Exit(1)
	}

	return k8s.Config{
		PrometheusURL:     shared.EnvOrDefault("PROMETHEUS_URL", "http://kube-prometheus-stack-prometheus.monitoring.svc.cluster.local:9090"),
		ClaudeModel:       shared.EnvOrDefault("CLAUDE_MODEL", "claude-sonnet-4-6"),
		CooldownSeconds:   cooldown,
		SkipResolved:      shared.EnvOrDefault("SKIP_RESOLVED", "true") != "false",
		Port:              shared.EnvOrDefault("PORT", "8080"),
		WebhookSecret:     webhookSecret,
		AllowedNamespaces: nsList,
		MaxLogBytes:       maxLogBytes,
		APIBaseURL:        shared.EnvOrDefault("API_BASE_URL", "https://api.anthropic.com/v1/messages"),
		APIKey:            apiKey,
	}
}

func main() {
	cfg := loadConfig()

	k8sConfig, err := rest.InClusterConfig()
	if err != nil {
		slog.Error("k8s config failed", "error", err)
		os.Exit(1)
	}
	clientset, err := kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		slog.Error("k8s client failed", "error", err)
		os.Exit(1)
	}

	claudeClient := shared.NewClaudeClient(cfg.BaseConfig())
	promClient := k8s.NewPrometheusClient(cfg.PrometheusURL)
	cooldownMgr := shared.NewCooldownManager()
	metrics := new(shared.AlertMetrics)
	publishers := []shared.Publisher{
		shared.NewNtfyPublisher(
			shared.EnvOrDefault("NTFY_PUBLISH_URL", "https://ntfy.example.com"),
			shared.EnvOrDefault("NTFY_PUBLISH_TOPIC", "kubernetes-analysis"),
			os.Getenv("NTFY_PUBLISH_TOKEN"),
		),
	}

	deps := k8s.PipelineDeps{
		Analyzer:     claudeClient,
		Publishers:   publishers,
		Cooldown:     cooldownMgr,
		Metrics:      metrics,
		SystemPrompt: systemPrompt,
		GatherContext: func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext {
			k8sAlert := alertPayloadToK8sAlert(alert)
			return k8s.GatherContext(ctx, promClient, clientset, k8sAlert, cfg)
		},
	}

	srv := shared.NewServer(shared.ServerConfig{
		Port:         cfg.Port,
		WorkerCount:  5,
		QueueSize:    20,
		DrainTimeout: 25 * time.Second,
	}, metrics, func(ctx context.Context, alert shared.AlertPayload) {
		k8s.ProcessAlert(ctx, deps, alert)
	})

	slog.Info("K8s Alert Analyzer started",
		"port", cfg.Port, "model", cfg.ClaudeModel,
		"apiBaseURL", cfg.APIBaseURL,
		"allowedNamespaces", cfg.AllowedNamespaces)

	handler := k8s.HandleWebhook(cfg, cooldownMgr, srv.Enqueue, metrics)
	srv.Run(handler)
}

func alertPayloadToK8sAlert(ap shared.AlertPayload) k8s.Alert {
	alert := k8s.Alert{
		Status:      ap.Fields["status"],
		Labels:      make(map[string]string),
		Annotations: make(map[string]string),
		Fingerprint: ap.Fingerprint,
	}
	for key, v := range ap.Fields {
		if strings.HasPrefix(key, "label:") {
			alert.Labels[strings.TrimPrefix(key, "label:")] = v
		} else if strings.HasPrefix(key, "annotation:") {
			alert.Annotations[strings.TrimPrefix(key, "annotation:")] = v
		}
	}
	return alert
}
```

- [ ] **Step 6: Run all tests**

```bash
go test ./... -count=1
```

Expected: all PASS.

- [ ] **Step 7: Build binary to verify compilation**

```bash
CGO_ENABLED=0 go build -o /dev/null ./cmd/k8s-analyzer/
```

Expected: builds without errors.

- [ ] **Step 8: Commit**

```bash
git add internal/k8s/pipeline.go internal/k8s/pipeline_test.go cmd/k8s-analyzer/main.go
git commit -m "refactor: extract K8s ProcessAlert pipeline, slim main.go using shared.Server"
```

---

## Task 11: CheckMK pipeline extraction and slim main.go

**Files:**
- Create: `internal/checkmk/pipeline.go`
- Create: `internal/checkmk/pipeline_test.go`
- Modify: `cmd/checkmk-analyzer/main.go`

- [ ] **Step 1: Write tests for ProcessAlert**

Create `internal/checkmk/pipeline_test.go`:

```go
package checkmk

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
)

type mockAnalyzer struct {
	result string
	err    error
}

func (m *mockAnalyzer) Analyze(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	return m.result, m.err
}

func (m *mockAnalyzer) RunToolLoop(ctx context.Context, systemPrompt, userPrompt string,
	tools []shared.Tool, maxRounds int, handleTool func(string, json.RawMessage) (string, error)) (string, error) {
	return m.result, m.err
}

type mockPublisher struct {
	published []string
	err       error
}

func (m *mockPublisher) Publish(ctx context.Context, title, priority, body string) error {
	m.published = append(m.published, body)
	return m.err
}

func (m *mockPublisher) Name() string { return "mock" }

func TestProcessAlert_NoSSH(t *testing.T) {
	pub := &mockPublisher{}
	cooldown := shared.NewCooldownManager()
	metrics := new(shared.AlertMetrics)

	deps := PipelineDeps{
		Analyzer:   &mockAnalyzer{result: "disk full analysis"},
		Publishers: []shared.Publisher{pub},
		Cooldown:   cooldown,
		Metrics:    metrics,
		SSHEnabled: false,
		GatherContext: func(ctx context.Context, alert shared.AlertPayload, hostInfo *HostInfo) shared.AnalysisContext {
			return shared.AnalysisContext{Sections: []shared.ContextSection{{Name: "Test", Content: "data"}}}
		},
		ValidateHost: func(ctx context.Context, hostname, hostAddress string) (*HostInfo, error) {
			return &HostInfo{}, nil
		},
	}

	alert := shared.AlertPayload{
		Fingerprint: "abc",
		Title:       "host1 - Disk Usage",
		Severity:    "critical",
		Source:      "checkmk",
		Fields:      map[string]string{"hostname": "host1", "host_address": "10.0.0.1"},
	}

	ProcessAlert(context.Background(), deps, alert)

	if metrics.AlertsProcessed.Load() != 1 {
		t.Errorf("AlertsProcessed = %d, want 1", metrics.AlertsProcessed.Load())
	}
	if len(pub.published) != 1 || pub.published[0] != "disk full analysis" {
		t.Errorf("published = %v", pub.published)
	}
}

func TestProcessAlert_AnalysisFails_CooldownCleared(t *testing.T) {
	pub := &mockPublisher{}
	cooldown := shared.NewCooldownManager()
	metrics := new(shared.AlertMetrics)

	deps := PipelineDeps{
		Analyzer:   &mockAnalyzer{err: context.DeadlineExceeded},
		Publishers: []shared.Publisher{pub},
		Cooldown:   cooldown,
		Metrics:    metrics,
		SSHEnabled: false,
		GatherContext: func(ctx context.Context, alert shared.AlertPayload, hostInfo *HostInfo) shared.AnalysisContext {
			return shared.AnalysisContext{}
		},
		ValidateHost: func(ctx context.Context, hostname, hostAddress string) (*HostInfo, error) {
			return nil, nil
		},
	}

	alert := shared.AlertPayload{Fingerprint: "abc", Title: "Test", Severity: "warning", Fields: map[string]string{"hostname": "h", "host_address": "1.2.3.4"}}
	ProcessAlert(context.Background(), deps, alert)

	if metrics.AlertsFailed.Load() != 1 {
		t.Errorf("AlertsFailed = %d, want 1", metrics.AlertsFailed.Load())
	}
}
```

- [ ] **Step 2: Implement checkmk pipeline**

Create `internal/checkmk/pipeline.go`:

```go
package checkmk

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
)

// PipelineDeps holds all dependencies for CheckMK alert processing.
type PipelineDeps struct {
	Analyzer      shared.Analyzer
	ToolRunner    shared.ToolLoopRunner
	Publishers    []shared.Publisher
	Cooldown      *shared.CooldownManager
	Metrics       *shared.AlertMetrics
	SSHEnabled    bool
	SSHDialer     *SSHDialer
	SSHConfig     Config // for denied commands, max rounds
	GatherContext func(ctx context.Context, alert shared.AlertPayload, hostInfo *HostInfo) shared.AnalysisContext
	ValidateHost  func(ctx context.Context, hostname, hostAddress string) (*HostInfo, error)
}

// ProcessAlert gathers context, optionally runs agentic SSH diagnostics, and publishes results.
func ProcessAlert(ctx context.Context, deps PipelineDeps, alert shared.AlertPayload) {
	hostname := alert.Fields["hostname"]
	hostAddress := alert.Fields["host_address"]

	slog.Info("processing CheckMK alert", "hostname", hostname, "service", alert.Fields["service_description"])

	hostInfo, validationErr := deps.ValidateHost(ctx, hostname, hostAddress)
	if validationErr != nil {
		slog.Warn("host validation failed", "error", validationErr, "hostname", hostname, "host_address", hostAddress)
	}

	actx := deps.GatherContext(ctx, alert, hostInfo)
	alertContext := actx.FormatForPrompt()

	sshOK := deps.SSHEnabled && validationErr == nil
	if deps.SSHEnabled && !sshOK {
		alertContext += "\n## Note\nSSH diagnostics unavailable: " + validationErr.Error() + "\n"
	}

	var analysis string

	if sshOK {
		var err error
		analysis, err = RunAgenticDiagnostics(ctx, deps.SSHConfig, deps.ToolRunner, deps.SSHDialer, hostAddress, alertContext, deps.SSHConfig.MaxAgentRounds)
		if err != nil {
			slog.Error("agentic diagnostics failed", "error", err)
			_ = shared.PublishAll(ctx, deps.Publishers,
				fmt.Sprintf("Analysis FAILED: %s", alert.Title), "5",
				fmt.Sprintf("**Agentic diagnostics failed** for %s: %v\n\nManual investigation needed.", alert.Title, err))
			deps.Cooldown.Clear(alert.Fingerprint)
			deps.Metrics.AlertsFailed.Add(1)
			return
		}
	} else {
		var err error
		analysis, err = deps.Analyzer.Analyze(ctx, AgentSystemPrompt, alertContext)
		if err != nil {
			slog.Error("analysis failed", "error", err)
			_ = shared.PublishAll(ctx, deps.Publishers,
				fmt.Sprintf("Analysis FAILED: %s", alert.Title), "5",
				fmt.Sprintf("**Analysis failed** for %s: %v\n\nManual investigation needed.", alert.Title, err))
			deps.Cooldown.Clear(alert.Fingerprint)
			deps.Metrics.AlertsFailed.Add(1)
			return
		}
	}

	priorityMap := map[string]string{"critical": "5", "warning": "4", "unknown": "3", "ok": "2"}
	priority := priorityMap[alert.Severity]
	if priority == "" {
		priority = "3"
	}

	title := fmt.Sprintf("Analysis: %s", alert.Title)
	if err := shared.PublishAll(ctx, deps.Publishers, title, priority, analysis); err != nil {
		deps.Cooldown.Clear(alert.Fingerprint)
		deps.Metrics.AlertsFailed.Add(1)
		return
	}

	deps.Metrics.AlertsProcessed.Add(1)
	slog.Info("analysis complete", "hostname", hostname)
}
```

- [ ] **Step 3: Run pipeline tests**

```bash
go test ./internal/checkmk/ -run TestProcessAlert -v -count=1
```

Expected: all PASS.

- [ ] **Step 4: Slim down checkmk main.go**

Replace `cmd/checkmk-analyzer/main.go` following the same pattern as task 10 — use `shared.EnvOrDefault`, `shared.ParseIntEnv`, `shared.RequireEnv`, `shared.NewServer`, `shared.NewClaudeClient`, `shared.NewNtfyPublisher`, and wire up `checkmk.PipelineDeps`.

Key differences from k8s:
- Construct `checkmk.NewAPIClient(cfg)` for host validation and context gathering
- Construct `checkmk.NewSSHDialer(cfg)` if SSH enabled (handle error at startup)
- Pass `claudeClient` as both `Analyzer` and `ToolRunner` (it implements both)
- SSH denylist warning: log `slog.Warn(...)` if `SSH_DENIED_COMMANDS` env is set but empty

- [ ] **Step 5: Run all tests and build**

```bash
go test ./... -count=1
CGO_ENABLED=0 go build -o /dev/null ./cmd/checkmk-analyzer/
```

Expected: all PASS, build succeeds.

- [ ] **Step 6: Commit**

```bash
git add internal/checkmk/pipeline.go internal/checkmk/pipeline_test.go cmd/checkmk-analyzer/main.go
git commit -m "refactor: extract CheckMK ProcessAlert pipeline, slim main.go using shared.Server"
```

---

## Task 12: Config validation

**Files:**
- Modify: `cmd/k8s-analyzer/main.go` (already using ParseIntEnv from task 10)
- Modify: `cmd/checkmk-analyzer/main.go` (already using ParseIntEnv from task 11)

This task is mostly done by tasks 10 and 11. Verify and add any remaining validation:

- [ ] **Step 1: Verify ParseIntEnv is used for all numeric configs**

Check that both `main.go` files use `shared.ParseIntEnv` with appropriate ranges for:
- `COOLDOWN_SECONDS` (0-86400)
- `MAX_LOG_BYTES` (256-1048576) — k8s only
- `MAX_AGENT_ROUNDS` (1-50) — checkmk only
- `PORT` — validate it's a valid port string (already validated by `ListenAndServe` but a check is cleaner)

- [ ] **Step 2: Verify SSH denylist warning is present**

In `cmd/checkmk-analyzer/main.go`, confirm the warning exists:

```go
if val, ok := os.LookupEnv("SSH_DENIED_COMMANDS"); ok && val == "" {
    slog.Warn("SSH_DENIED_COMMANDS is empty — all commands are allowed, no denylist active")
}
```

- [ ] **Step 3: Run all tests and builds**

```bash
go test ./... -count=1
CGO_ENABLED=0 go build -o /dev/null ./cmd/k8s-analyzer/
CGO_ENABLED=0 go build -o /dev/null ./cmd/checkmk-analyzer/
```

Expected: all PASS.

- [ ] **Step 4: Commit (if any changes)**

```bash
git add cmd/
git commit -m "feat: validate config at startup, warn on empty SSH denylist"
```

---

## Task 13: Observability improvements

**Files:**
- Modify: `internal/shared/metrics.go`
- Modify: `internal/shared/metrics_test.go`
- Modify: `internal/shared/server.go`
- Modify: `cmd/k8s-analyzer/main.go`
- Modify: `cmd/checkmk-analyzer/main.go`

- [ ] **Step 1: Add processing duration tracking to AlertMetrics**

In `internal/shared/metrics.go`, add a simple processing duration tracker. To avoid pulling in a Prometheus client library, use a mutex-protected slice of recent durations for percentile calculation, or simpler: track count, sum, and expose as counters (sum/count = average):

```go
// Add to AlertMetrics:
ProcessingDurationSum  atomic.Int64 // microseconds
ProcessingDurationCount atomic.Int64
```

Add to `MetricsHandler`:

```go
fmt.Fprintf(w, "# HELP alert_analyzer_processing_duration_seconds_sum Total processing time.\n")
fmt.Fprintf(w, "# TYPE alert_analyzer_processing_duration_seconds_sum counter\n")
fmt.Fprintf(w, "alert_analyzer_processing_duration_seconds_sum %f\n",
    float64(m.ProcessingDurationSum.Load())/1e6)
fmt.Fprintf(w, "# HELP alert_analyzer_processing_duration_seconds_count Total alerts processed (for avg calculation).\n")
fmt.Fprintf(w, "# TYPE alert_analyzer_processing_duration_seconds_count counter\n")
fmt.Fprintf(w, "alert_analyzer_processing_duration_seconds_count %d\n",
    m.ProcessingDurationCount.Load())
```

- [ ] **Step 2: Track duration in pipelines**

In both `k8s/pipeline.go` and `checkmk/pipeline.go`, wrap processing with timing:

```go
func ProcessAlert(ctx context.Context, deps PipelineDeps, alert shared.AlertPayload) {
    start := time.Now()
    defer func() {
        deps.Metrics.ProcessingDurationSum.Add(time.Since(start).Microseconds())
        deps.Metrics.ProcessingDurationCount.Add(1)
    }()
    // ... rest of processing
}
```

- [ ] **Step 3: Add configurable log level**

In both `cmd/*/main.go`, add at the top of `main()`:

```go
var logLevel slog.Level
switch strings.ToLower(shared.EnvOrDefault("LOG_LEVEL", "info")) {
case "debug":
    logLevel = slog.LevelDebug
case "warn":
    logLevel = slog.LevelWarn
case "error":
    logLevel = slog.LevelError
default:
    logLevel = slog.LevelInfo
}

logFormat := shared.EnvOrDefault("LOG_FORMAT", "text")
var handler slog.Handler
if logFormat == "json" {
    handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
} else {
    handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
}
slog.SetDefault(slog.New(handler))
```

- [ ] **Step 4: Add /ready endpoint to Server**

In `internal/shared/server.go`, add a `ReadyCheck` field:

```go
type Server struct {
    // ...
    ReadyCheck func(ctx context.Context) error // optional, nil = always ready
}
```

In `BuildMux`, add:

```go
mux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
    if s.ReadyCheck != nil {
        checkCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
        defer cancel()
        if err := s.ReadyCheck(checkCtx); err != nil {
            w.WriteHeader(http.StatusServiceUnavailable)
            fmt.Fprintf(w, "not ready: %v", err)
            return
        }
    }
    w.WriteHeader(http.StatusOK)
    fmt.Fprint(w, "ready")
})
```

For k8s, set `ReadyCheck` to ping Prometheus. For checkmk, ping CheckMK API. Both are optional — if not set, `/ready` always returns 200.

- [ ] **Step 5: Run all tests**

```bash
go test ./... -count=1
```

Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/shared/metrics.go internal/shared/metrics_test.go internal/shared/server.go internal/shared/server_test.go internal/k8s/pipeline.go internal/checkmk/pipeline.go cmd/k8s-analyzer/main.go cmd/checkmk-analyzer/main.go
git commit -m "feat: add processing duration metrics, configurable logging, /ready endpoint"
```

---

## Task 14: CI lint config and final cleanup

**Files:**
- Create: `.golangci.yml`

- [ ] **Step 1: Create golangci-lint config**

Create `.golangci.yml`:

```yaml
run:
  timeout: 5m

linters:
  enable:
    - errcheck
    - govet
    - staticcheck
    - unused
    - ineffassign
    - gosimple

issues:
  exclude-dirs:
    - docs
```

- [ ] **Step 2: Run lint locally to check for issues**

```bash
golangci-lint run ./...
```

Fix any issues found.

- [ ] **Step 3: Run full test suite one final time**

```bash
go test -race -count=1 ./...
CGO_ENABLED=0 go build -o /dev/null ./cmd/k8s-analyzer/
CGO_ENABLED=0 go build -o /dev/null ./cmd/checkmk-analyzer/
```

Expected: all PASS, both binaries build.

- [ ] **Step 4: Commit**

```bash
git add .golangci.yml
git commit -m "chore: add golangci-lint config"
```

---

## Dependency Graph

```
Task 1  (CI)           ─── independent
Task 2  (LimitReader)  ─── independent
Task 3  (Types)        ─── independent
Task 4  (Config)       ─── independent
Task 5  (ClaudeClient) ─── depends on: 3
Task 6  (Ntfy DI)      ─── independent
Task 7  (K8s DI)       ─── independent
Task 8  (CheckMK DI)   ─── depends on: 5
Task 9  (Server)       ─── independent
Task 10 (K8s pipe)     ─── depends on: 4, 5, 6, 7, 9
Task 11 (CMK pipe)     ─── depends on: 4, 5, 6, 8, 9
Task 12 (Validation)   ─── depends on: 10, 11
Task 13 (Observability)─── depends on: 9, 10, 11
Task 14 (Lint config)  ─── independent
```

**Recommended sequential order:** 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14
