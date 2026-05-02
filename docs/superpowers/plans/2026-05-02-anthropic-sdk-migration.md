# Anthropic SDK Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the hand-rolled Claude HTTP client at `internal/shared/claude.go` with the official `anthropic-sdk-go`, restoring OpenRouter compatibility, while keeping `internal/k8s/pipeline.go` and `internal/checkmk/pipeline.go` source-unchanged.

**Architecture:** SDK-based `ClaudeClient` + custom `http.Transport` (`LimitedTransport`) for the 2 MiB body cap and latency histogram. Tool types switch from hand-rolled `shared.Tool` to `anthropic.ToolUnionParam`. Auth env vars hard-cut from `API_KEY` / `API_BASE_URL` to `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN` / `ANTHROPIC_BASE_URL`.

**Tech Stack:** Go 1.26+, `github.com/anthropics/anthropic-sdk-go`, `github.com/prometheus/client_golang`, `httptest`.

**Spec:** [`docs/superpowers/specs/2026-05-02-anthropic-sdk-migration-design.md`](../specs/2026-05-02-anthropic-sdk-migration-design.md)

---

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `go.mod`, `go.sum` | modify | Add `anthropic-sdk-go` dependency |
| `internal/shared/payload.go` | create | Non-tool shared types: `AnalysisContext`, `ContextSection`, `Publisher`, `AlertPayload`, `BaseConfig` |
| `internal/shared/transport.go` | create | `LimitedTransport` `http.RoundTripper` — body cap + latency histogram via `Close()`-triggered observation |
| `internal/shared/transport_test.go` | create | Unit tests for `LimitedTransport` against a mock inner transport |
| `internal/shared/types.go` | delete | Hand-rolled tool types replaced by SDK types |
| `internal/shared/interfaces.go` | modify | `ToolLoopRunner.RunToolLoop` `tools` parameter element type → `anthropic.ToolUnionParam` |
| `internal/shared/claude.go` | rewrite | SDK-based `ClaudeClient` (~150 lines) |
| `internal/shared/claude_test.go` | migrate | Drop 4 tests, rewrite typed-error tests, update constructor calls, add new auth-header tests |
| `internal/k8s/agent.go` | modify | Declare `kubectlTool`, `promqlTool` as `anthropic.ToolUnionParam` |
| `internal/k8s/agent_test.go` | modify | Mock `ToolLoopRunner.RunToolLoop` signature → `[]anthropic.ToolUnionParam` |
| `internal/k8s/pipeline_test.go` | modify | Same |
| `internal/checkmk/agent.go` | modify | Declare `sshTool` as `anthropic.ToolUnionParam` |
| `internal/checkmk/agent_test.go` | modify | Same as k8s mock-signature change |
| `internal/checkmk/pipeline_test.go` | modify | Same |
| `internal/k8s/config.go` (or wherever `Config` and `BaseConfig()` live) | modify | Add `AuthToken` field |
| `internal/checkmk/config.go` (or wherever `Config` and `BaseConfig()` live) | modify | Add `AuthToken` field |
| `cmd/k8s-analyzer/main.go` | modify | Env-var rename, startup auth validation, `os.Unsetenv`, transport wiring |
| `cmd/k8s-analyzer/main_test.go` | create | Startup-auth-validation tests |
| `cmd/checkmk-analyzer/main.go` | modify | Same |
| `cmd/checkmk-analyzer/main_test.go` | create | Same |
| `docs/cost-and-storm-protection.md` | modify | Drop "OpenRouter compatibility deferred" notes; add "OpenRouter setup" section |
| `CLAUDE.md` | modify | Drop breaking-change deferral note; mention SDK |
| `README.md` | modify | LLM provider section explains SDK env vars |

---

## Task 1: Add `anthropic-sdk-go` dependency

**Files:**
- Modify: `go.mod`, `go.sum`, `internal/shared/types.go`

- [ ] **Step 1: Confirm baseline tests pass**

Run: `go test ./...`
Expected: all tests pass (current baseline).

- [ ] **Step 2: Add the SDK dependency**

Run: `go get github.com/anthropics/anthropic-sdk-go@latest`

- [ ] **Step 2.5: Add a temporary blank import to keep the SDK as a direct dependency**

Without something importing the SDK, `go mod tidy` strips `github.com/anthropics/anthropic-sdk-go` from `go.mod` entirely. Add a blank import to `internal/shared/types.go` so the dependency survives. This file is deleted entirely in Task 5, so the blank import is removed naturally — no follow-up cleanup needed.

Edit `internal/shared/types.go` to add inside the existing `import (...)` block:

```go
// Blank import keeps the SDK as a direct dependency until Task 5 introduces
// real imports. The whole file is deleted in Task 5; this line goes with it.
_ "github.com/anthropics/anthropic-sdk-go"
```

- [ ] **Step 3: Tidy modules**

Run: `go mod tidy`

- [ ] **Step 4: Confirm build still works**

Run: `CGO_ENABLED=0 go build ./...`
Expected: success, no output.

- [ ] **Step 5: Confirm tests still pass**

Run: `go test ./...`
Expected: same baseline as Step 1 — no behavior change yet.

- [ ] **Step 6: Verify `go.mod` lists the SDK as a direct dependency**

Run: `grep 'anthropics/anthropic-sdk-go' go.mod`
Expected: a line under `require (...)` block (not in `// indirect` section).

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum internal/shared/types.go
git commit -m "chore(deps): add anthropic-sdk-go for SDK migration"
```

---

## Task 2: Create `payload.go` with non-tool types

**Files:**
- Create: `internal/shared/payload.go`
- Modify: `internal/shared/types.go` (remove the non-tool types that move to payload.go)

- [ ] **Step 1: Create the new file**

Create `internal/shared/payload.go` with the following exact content:

```go
package shared

import (
	"context"
	"strings"
)

// AnalysisContext holds named text sections injected into the Claude user prompt.
type AnalysisContext struct {
	Sections []ContextSection
}

type ContextSection struct {
	Name    string
	Content string
}

// FormatForPrompt renders all sections as a single string for Claude.
func (ac AnalysisContext) FormatForPrompt() string {
	var b strings.Builder
	for _, sec := range ac.Sections {
		b.WriteString("## ")
		b.WriteString(sec.Name)
		b.WriteByte('\n')
		b.WriteString(sec.Content)
		b.WriteString("\n\n")
	}
	return b.String()
}

// Publisher sends analysis results to a notification target.
type Publisher interface {
	Publish(ctx context.Context, title, priority, body string) error
	Name() string
}

// AlertPayload is the common alert representation.
type AlertPayload struct {
	Fingerprint   string
	Title         string
	Severity      string            // free-form, used for ntfy display (preserved)
	SeverityLevel Severity          // normalized, used for AnalysisPolicy routing
	Source        string            // "k8s" or "checkmk"
	Fields        map[string]string // source-specific key-value pairs
}

// BaseConfig holds configuration shared by all analyzers.
type BaseConfig struct {
	ClaudeModel     string
	CooldownSeconds int
	Port            string
	MetricsPort     string
	WebhookSecret   string
	APIBaseURL      string
	APIKey          string
}
```

- [ ] **Step 2: Remove the moved types from `internal/shared/types.go`**

Delete lines 1–57 of `internal/shared/types.go` (the package declaration, imports, and the `AnalysisContext`, `ContextSection`, `FormatForPrompt`, `Publisher`, `AlertPayload`, `BaseConfig` definitions). Keep the `// Tool-use types for agentic Claude interactions.` comment and everything below it.

After the edit, `internal/shared/types.go` must start with:

```go
package shared

import (
	"encoding/json"
)

// Tool-use types for agentic Claude interactions.

// CacheControl marks a content block for prompt caching.
type CacheControl struct {
	Type string `json:"type"` // currently only "ephemeral"
}
```

(Keep `encoding/json` because the remaining tool types use `json.RawMessage`.)

- [ ] **Step 3: Verify build**

Run: `CGO_ENABLED=0 go build ./...`
Expected: success.

- [ ] **Step 4: Verify tests**

Run: `go test ./...`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/shared/payload.go internal/shared/types.go
git commit -m "refactor(shared): extract non-tool types into payload.go"
```

---

## Task 3: Add `AuthToken` field to `BaseConfig` and propagate to package configs

**Files:**
- Modify: `internal/shared/payload.go` (add `AuthToken` field)
- Modify: `internal/k8s/config.go` (or the file declaring `k8s.Config`)
- Modify: `internal/checkmk/config.go` (or the file declaring `checkmk.Config`)

- [ ] **Step 1: Locate the `k8s.Config` declaration**

Run: `grep -rn 'type Config struct' internal/k8s/`
Note the file and line.

- [ ] **Step 2: Locate the `checkmk.Config` declaration**

Run: `grep -rn 'type Config struct' internal/checkmk/`
Note the file and line.

- [ ] **Step 3: Locate the `BaseConfig()` methods**

Run: `grep -rn 'func.*BaseConfig() shared.BaseConfig' internal/`
Note both files.

- [ ] **Step 4: Add `AuthToken string` field to `BaseConfig` in `internal/shared/payload.go`**

Replace the `BaseConfig` struct definition with:

```go
// BaseConfig holds configuration shared by all analyzers.
type BaseConfig struct {
	ClaudeModel     string
	CooldownSeconds int
	Port            string
	MetricsPort     string
	WebhookSecret   string

	APIBaseURL string // ANTHROPIC_BASE_URL
	APIKey     string // ANTHROPIC_API_KEY  (sets x-api-key)
	AuthToken  string // ANTHROPIC_AUTH_TOKEN (sets Authorization: Bearer)
}
```

- [ ] **Step 5: Add `AuthToken string` field to `k8s.Config`**

In the file from Step 1, add `AuthToken string` immediately after the existing `APIKey string` field. The file's `Config` struct should now contain both fields.

- [ ] **Step 6: Add `AuthToken string` field to `checkmk.Config`**

Same as Step 5 in the file from Step 2.

- [ ] **Step 7: Update both `BaseConfig()` methods to map `AuthToken`**

In each `BaseConfig()` method, add the line `AuthToken: c.AuthToken,` (or `cfg.AuthToken,` matching the receiver name) inside the returned `shared.BaseConfig{...}` literal.

- [ ] **Step 8: Verify build**

Run: `CGO_ENABLED=0 go build ./...`
Expected: success. `cfg.AuthToken` is populated to `""` because `main.go` does not yet read it — no behavior change.

- [ ] **Step 9: Verify tests**

Run: `go test ./...`
Expected: all tests pass.

- [ ] **Step 10: Commit**

```bash
git add internal/shared/payload.go internal/k8s/*.go internal/checkmk/*.go
git commit -m "refactor(config): add AuthToken field, plumbed through k8s and checkmk Config"
```

---

## Task 4: Build `LimitedTransport` (TDD)

**Files:**
- Create: `internal/shared/transport.go`
- Create: `internal/shared/transport_test.go`

This task uses red-green TDD across five tests. Each subsection adds one test, watches it fail, implements just enough code to pass, then verifies green. Final commit at the end of the task.

### Subtask 4a: Body cap

- [ ] **Step 1: Write the failing test**

Create `internal/shared/transport_test.go` with:

```go
package shared

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

type mockRoundTripper struct {
	resp    *http.Response
	err     error
	calls   atomic.Int32
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	m.calls.Add(1)
	if m.err != nil {
		return nil, m.err
	}
	return m.resp, nil
}

func newOKResponse(body []byte) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}

func TestLimitedTransport_OversizedBodyCapped(t *testing.T) {
	oversize := make([]byte, MaxResponseBytes+1024)
	for i := range oversize {
		oversize[i] = 'A'
	}
	inner := &mockRoundTripper{resp: newOKResponse(oversize)}

	lt := NewLimitedTransport(inner, nil)
	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)

	resp, err := lt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	read, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if int64(len(read)) != MaxResponseBytes {
		t.Errorf("expected body capped to %d bytes, got %d", MaxResponseBytes, len(read))
	}
}
```

- [ ] **Step 2: Run the test — expect a build failure**

Run: `go test ./internal/shared/ -run TestLimitedTransport_OversizedBodyCapped -v`
Expected: build error referencing `MaxResponseBytes`, `NewLimitedTransport` undefined.

- [ ] **Step 3: Write the minimal implementation**

Create `internal/shared/transport.go`:

```go
package shared

import (
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// MaxResponseBytes bounds the amount of data read from an API response body
// to prevent a malicious or buggy upstream from exhausting memory.
const MaxResponseBytes = 2 * 1024 * 1024 // 2 MiB

// LimitedTransport wraps an http.RoundTripper to (a) cap response body size at
// MaxResponseBytes and (b) observe round-trip latency in a Prometheus histogram
// when the body is closed.
type LimitedTransport struct {
	inner             http.RoundTripper
	maxBytes          int64
	durationHistogram prometheus.Observer // optional; nil = no observation
}

// NewLimitedTransport returns a LimitedTransport around inner. inner=nil falls
// back to http.DefaultTransport. hist=nil disables histogram observation.
func NewLimitedTransport(inner http.RoundTripper, hist prometheus.Observer) *LimitedTransport {
	if inner == nil {
		inner = http.DefaultTransport
	}
	return &LimitedTransport{
		inner:             inner,
		maxBytes:          MaxResponseBytes,
		durationHistogram: hist,
	}
}

func (lt *LimitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := lt.inner.RoundTrip(req)
	if err != nil {
		lt.observe(start)
		return nil, err
	}
	resp.Body = &timedLimitedReadCloser{
		r:       io.LimitReader(resp.Body, lt.maxBytes),
		c:       resp.Body,
		start:   start,
		observe: lt.observe,
	}
	return resp, nil
}

func (lt *LimitedTransport) observe(start time.Time) {
	if lt.durationHistogram != nil {
		lt.durationHistogram.Observe(time.Since(start).Seconds())
	}
}

// timedLimitedReadCloser wraps a response body so that:
//   - reads are bounded by an io.LimitReader (defense-in-depth body cap)
//   - the latency histogram is observed exactly once when Close is called,
//     mirroring the pre-migration "observe after full body read" semantics
type timedLimitedReadCloser struct {
	r       io.Reader
	c       io.Closer
	start   time.Time
	observe func(time.Time)
	once    sync.Once
}

func (t *timedLimitedReadCloser) Read(p []byte) (int, error) {
	return t.r.Read(p)
}

func (t *timedLimitedReadCloser) Close() error {
	t.once.Do(func() { t.observe(t.start) })
	return t.c.Close()
}
```

- [ ] **Step 4: Run the test — expect green**

Run: `go test ./internal/shared/ -run TestLimitedTransport_OversizedBodyCapped -v`
Expected: PASS.

### Subtask 4b: Histogram observed on Close (Phase-1 semantics)

- [ ] **Step 5: Add the failing test**

Append to `internal/shared/transport_test.go`:

```go
func TestLimitedTransport_HistogramObservedAfterBodyClose(t *testing.T) {
	hist := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "test_after_close_seconds",
		Help: "test",
	})
	inner := &mockRoundTripper{resp: newOKResponse([]byte(`{"ok":true}`))}
	lt := NewLimitedTransport(inner, hist)

	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	resp, err := lt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Histogram must NOT be observed yet — only RoundTrip has returned.
	var m1 dto.Metric
	if err := hist.Write(&m1); err != nil {
		t.Fatalf("hist.Write: %v", err)
	}
	if m1.Histogram.GetSampleCount() != 0 {
		t.Errorf("histogram should not be observed before Close, got count=%d", m1.Histogram.GetSampleCount())
	}

	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	var m2 dto.Metric
	if err := hist.Write(&m2); err != nil {
		t.Fatalf("hist.Write: %v", err)
	}
	if m2.Histogram.GetSampleCount() != 1 {
		t.Errorf("histogram should be observed exactly once after Close, got count=%d", m2.Histogram.GetSampleCount())
	}

	// Idempotency: second Close must not double-count.
	_ = resp.Body.Close()
	var m3 dto.Metric
	_ = hist.Write(&m3)
	if m3.Histogram.GetSampleCount() != 1 {
		t.Errorf("second Close should not double-count, got count=%d", m3.Histogram.GetSampleCount())
	}
}
```

- [ ] **Step 6: Run — expect green (the implementation already covers this)**

Run: `go test ./internal/shared/ -run TestLimitedTransport_HistogramObservedAfterBodyClose -v`
Expected: PASS.

### Subtask 4c: Histogram observed on transport error

- [ ] **Step 7: Add the failing test**

Append:

```go
func TestLimitedTransport_HistogramObservedOnTransportError(t *testing.T) {
	hist := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "test_transport_error_seconds",
		Help: "test",
	})
	inner := &mockRoundTripper{err: errors.New("connection refused")}
	lt := NewLimitedTransport(inner, hist)

	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	_, err := lt.RoundTrip(req)
	if err == nil {
		t.Fatal("expected an error from inner.RoundTrip")
	}

	var m dto.Metric
	if err := hist.Write(&m); err != nil {
		t.Fatalf("hist.Write: %v", err)
	}
	if m.Histogram.GetSampleCount() != 1 {
		t.Errorf("histogram should be observed on transport error, got count=%d", m.Histogram.GetSampleCount())
	}
}
```

- [ ] **Step 8: Run — expect green**

Run: `go test ./internal/shared/ -run TestLimitedTransport_HistogramObservedOnTransportError -v`
Expected: PASS.

### Subtask 4d: Histogram observed on success and on non-OK status

- [ ] **Step 9: Add both tests**

Append:

```go
func TestLimitedTransport_HistogramObservedOnSuccess(t *testing.T) {
	hist := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "test_success_seconds",
		Help: "test",
	})
	inner := &mockRoundTripper{resp: newOKResponse([]byte(`{"ok":true}`))}
	lt := NewLimitedTransport(inner, hist)

	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	resp, err := lt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var m dto.Metric
	_ = hist.Write(&m)
	if m.Histogram.GetSampleCount() != 1 {
		t.Errorf("expected 1 observation on success, got %d", m.Histogram.GetSampleCount())
	}
	if m.Histogram.GetSampleSum() <= 0 {
		t.Errorf("expected positive duration, got %f", m.Histogram.GetSampleSum())
	}
}

func TestLimitedTransport_HistogramObservedOnNonOK(t *testing.T) {
	hist := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "test_nonok_seconds",
		Help: "test",
	})
	resp429 := &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Body:       io.NopCloser(bytes.NewReader([]byte(`rate limited`))),
	}
	inner := &mockRoundTripper{resp: resp429}
	lt := NewLimitedTransport(inner, hist)

	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	resp, err := lt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var m dto.Metric
	_ = hist.Write(&m)
	if m.Histogram.GetSampleCount() != 1 {
		t.Errorf("expected 1 observation on non-OK, got %d", m.Histogram.GetSampleCount())
	}
}
```

- [ ] **Step 10: Run all transport tests**

Run: `go test ./internal/shared/ -run TestLimitedTransport -v`
Expected: 5 PASS.

- [ ] **Step 11: Run with `-race`**

Run: `go test ./internal/shared/ -run TestLimitedTransport -race`
Expected: 5 PASS, no race warnings.

- [ ] **Step 12: Commit**

```bash
git add internal/shared/transport.go internal/shared/transport_test.go
git commit -m "feat(shared): add LimitedTransport for body cap and latency histogram"
```

---

## Task 5: Atomic SDK switch — interfaces, tools, claude.go, tests, types.go deletion

This is a non-decomposable refactor: the moment `interfaces.go` switches to `[]anthropic.ToolUnionParam`, the old `claude.go` no longer compiles, and the old tool declarations no longer match. All sub-steps are performed in one working tree, ending in a single commit. The plan numbers each sub-step so you can track progress, but you do not run `go build` until step 5.G.

**Files:**
- Modify: `internal/shared/interfaces.go`
- Rewrite: `internal/shared/claude.go`
- Migrate: `internal/shared/claude_test.go`
- Modify: `internal/k8s/agent.go`
- Modify: `internal/k8s/agent_test.go`
- Modify: `internal/k8s/pipeline_test.go`
- Modify: `internal/checkmk/agent.go`
- Modify: `internal/checkmk/agent_test.go`
- Modify: `internal/checkmk/pipeline_test.go`
- Delete: `internal/shared/types.go`

### Step 5.A — Update `interfaces.go`

- [ ] **5.A.1: Replace the entire content of `internal/shared/interfaces.go` with:**

```go
package shared

import (
	"context"
	"encoding/json"

	"github.com/anthropics/anthropic-sdk-go"
)

// Analyzer performs single-turn Claude analysis.
type Analyzer interface {
	Analyze(ctx context.Context, model, systemPrompt, userPrompt string) (string, error)
}

// ToolLoopRunner performs multi-turn Claude tool-use conversations.
type ToolLoopRunner interface {
	RunToolLoop(
		ctx context.Context,
		model, systemPrompt, userPrompt string,
		tools []anthropic.ToolUnionParam,
		maxRounds int,
		handleTool func(name string, input json.RawMessage) (string, error),
	) (analysis string, rounds int, exhausted bool, err error)
}
```

### Step 5.B — Update `internal/k8s/agent.go` tool declarations

- [ ] **5.B.1: Add the SDK import**

In `internal/k8s/agent.go` add `"github.com/anthropics/anthropic-sdk-go"` to the import block.

- [ ] **5.B.2: Replace `kubectlTool`**

Replace the entire `var kubectlTool = shared.Tool{...}` block (lines 230–246, including the leading comment at lines 230–231) with:

```go
// kubectlTool is the Claude tool definition for argv-based kubectl execution.
// The schema mirrors checkmk's execute_command tool — one argv array, no shell.
var kubectlTool = anthropic.ToolUnionParam{
	OfTool: &anthropic.ToolParam{
		Name:        "kubectl_exec",
		Description: anthropic.String("Run a read-only kubectl command. The command is passed as an argv array (no shell). Examples: [\"get\",\"pods\",\"-n\",\"monitoring\",\"-o\",\"wide\"], [\"describe\",\"pod\",\"prom-0\",\"-n\",\"monitoring\"], [\"logs\",\"pod-x\",\"-n\",\"db\",\"--tail=100\"], [\"top\",\"nodes\"]. Allowed verbs: get, describe, logs, top, events, explain, version, api-resources, api-versions, cluster-info, auth can-i, rollout history."),
		InputSchema: anthropic.ToolInputSchemaParam{
			Properties: map[string]any{
				"command": map[string]any{
					"type":        "array",
					"description": "kubectl arguments as argv array, without the leading 'kubectl'",
					"items":       map[string]any{"type": "string"},
				},
			},
			Required: []string{"command"},
		},
	},
}
```

- [ ] **5.B.3: Replace `promqlTool`**

Replace the `var promqlTool = shared.Tool{...}` block (lines 248–263) with:

```go
// promqlTool is the Claude tool definition for arbitrary PromQL queries
// against the configured Prometheus instance.
var promqlTool = anthropic.ToolUnionParam{
	OfTool: &anthropic.ToolParam{
		Name:        "promql_query",
		Description: anthropic.String("Run a PromQL query against Prometheus. Returns time-series results. Example: 'rate(http_requests_total[5m])'."),
		InputSchema: anthropic.ToolInputSchemaParam{
			Properties: map[string]any{
				"query": map[string]any{
					"type":        "string",
					"description": "PromQL expression",
				},
			},
			Required: []string{"query"},
		},
	},
}
```

- [ ] **5.B.4: Update the `RunToolLoop` call site at `internal/k8s/agent.go:469`**

Find the line that today reads:
```go
[]shared.Tool{kubectlTool, promqlTool},
```
Replace it with:
```go
[]anthropic.ToolUnionParam{kubectlTool, promqlTool},
```

### Step 5.C — Update `internal/checkmk/agent.go` tool declaration

- [ ] **5.C.1: Add the SDK import**

In `internal/checkmk/agent.go` add `"github.com/anthropics/anthropic-sdk-go"` to the import block.

- [ ] **5.C.2: Replace `sshTool`**

Replace the `var sshTool = shared.Tool{...}` block (lines 69–83) with:

```go
var sshTool = anthropic.ToolUnionParam{
	OfTool: &anthropic.ToolParam{
		Name:        "execute_command",
		Description: anthropic.String("Execute a diagnostic command on the remote host via SSH. The command is passed as an argv array (not interpreted by a shell). Only read-only commands are allowed."),
		InputSchema: anthropic.ToolInputSchemaParam{
			Properties: map[string]any{
				"command": map[string]any{
					"type":        "array",
					"description": "Command and arguments as array, e.g. [\"df\", \"-h\"] or [\"journalctl\", \"--no-pager\", \"-n\", \"50\"]",
					"items":       map[string]any{"type": "string"},
				},
			},
			Required: []string{"command"},
		},
	},
}
```

- [ ] **5.C.3: Update the `RunToolLoop` call site at `internal/checkmk/agent.go:928`**

Find the line that reads:
```go
[]shared.Tool{sshTool}, maxRounds, wrappedHandleTool,
```
Replace it with:
```go
[]anthropic.ToolUnionParam{sshTool}, maxRounds, wrappedHandleTool,
```

### Step 5.D — Update mock `RunToolLoop` signatures in 4 test files

- [ ] **5.D.1: List all mock signatures**

Run:
```bash
grep -rn 'tools \[\]shared\.Tool' internal/k8s/ internal/checkmk/
```
Expected hits: 4 lines across `internal/k8s/agent_test.go`, `internal/k8s/pipeline_test.go`, `internal/checkmk/agent_test.go`, `internal/checkmk/pipeline_test.go`.

- [ ] **5.D.2: For each of those four files, add the SDK import and rewrite the mock signature**

In each file:
- Add `"github.com/anthropics/anthropic-sdk-go"` to the imports block.
- Replace `tools []shared.Tool` (or `_ []shared.Tool`) with `tools []anthropic.ToolUnionParam` (or `_ []anthropic.ToolUnionParam` if the parameter is unused).

The exact spots are noted in each file — they are mock implementations of the `ToolLoopRunner` interface. The replacement only changes the parameter type; do not touch the function bodies.

### Step 5.E — Rewrite `internal/shared/claude.go`

- [ ] **5.E.1: Replace the entire content of `internal/shared/claude.go` with:**

```go
package shared

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// ClaudeClient wraps the Anthropic SDK client and adds:
//   - per-call model selection (with optional fallback to a default)
//   - 3-breakpoint prompt-cache plumbing on system, tools, and tool_result
//   - atomic per-analysis token-usage recording into Prometheus counters
//   - forced-summary turn at the end of an exhausted tool loop
type ClaudeClient struct {
	sdk   *anthropic.Client
	Model string

	// metrics and source enable per-call token-counter recording.
	// nil/empty for tests that do not assert metrics.
	metrics *AlertMetrics
	source  string
}

// NewClaudeClient returns a ClaudeClient wired against transport. The transport
// is responsible for body-size capping and latency-histogram observation; the
// SDK client itself only deals with API semantics.
//
// cfg.APIKey and cfg.AuthToken are passed unconditionally so the SDK never
// falls back to its own ANTHROPIC_*_KEY / ANTHROPIC_AUTH_TOKEN env-var
// lookups. main.go is the single source of truth for these values and is
// expected to have unset the env vars before this constructor is called.
func NewClaudeClient(cfg BaseConfig, transport http.RoundTripper) *ClaudeClient {
	httpClient := &http.Client{Timeout: 120 * time.Second, Transport: transport}

	opts := []option.RequestOption{
		option.WithHTTPClient(httpClient),
		option.WithMaxRetries(2),
		option.WithAPIKey(cfg.APIKey),
		option.WithAuthToken(cfg.AuthToken),
	}
	if cfg.APIBaseURL != "" {
		opts = append(opts, option.WithBaseURL(cfg.APIBaseURL))
	}
	sdk := anthropic.NewClient(opts...)
	return &ClaudeClient{sdk: &sdk, Model: cfg.ClaudeModel}
}

// WithPrometheusMetrics attaches the AlertMetrics so every Analyze and
// RunToolLoop call records token usage. Latency observation is wired in the
// transport, not here.
func (c *ClaudeClient) WithPrometheusMetrics(m *AlertMetrics, source string) *ClaudeClient {
	c.metrics = m
	c.source = source
	return c
}

// systemBlocks builds the system field with a single text block carrying
// a cache_control breakpoint at its tail. This is breakpoint #1 of the
// 4-breakpoint Anthropic budget; #2 is on the tools array, #3 on the
// last tool_result of the running conversation.
func systemBlocks(prompt string) []anthropic.TextBlockParam {
	return []anthropic.TextBlockParam{{
		Text:         prompt,
		CacheControl: anthropic.NewCacheControlEphemeralParam(),
	}}
}

// toolsWithCachedTail returns a copy of tools with cache_control attached to
// the OfTool variant of the last element. Tools is a small slice (1-2
// elements), so the copy cost is negligible.
func toolsWithCachedTail(tools []anthropic.ToolUnionParam) []anthropic.ToolUnionParam {
	if len(tools) == 0 {
		return tools
	}
	out := make([]anthropic.ToolUnionParam, len(tools))
	copy(out, tools)
	last := &out[len(out)-1]
	if last.OfTool != nil {
		// Copy the inner ToolParam so we don't mutate the caller's value.
		toolCopy := *last.OfTool
		toolCopy.CacheControl = anthropic.NewCacheControlEphemeralParam()
		last.OfTool = &toolCopy
	}
	return out
}

// extractText concatenates all text blocks in a Claude response message.
func extractText(msg *anthropic.Message) string {
	var parts []string
	for _, block := range msg.Content {
		if tb, ok := block.AsAny().(anthropic.TextBlock); ok && tb.Text != "" {
			parts = append(parts, tb.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// Analyze sends a single-turn analysis request to the Claude API.
// model is the model to use for this request; if empty, c.Model is used.
func (c *ClaudeClient) Analyze(ctx context.Context, model, systemPrompt, userPrompt string) (string, error) {
	if model == "" {
		model = c.Model
	}

	msg, err := c.sdk.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(model),
		MaxTokens: 2048,
		System:    systemBlocks(systemPrompt),
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(userPrompt)),
		},
	})
	if err != nil {
		return "", err
	}

	slog.Info("Claude analysis complete",
		"model", model,
		"inputTokens", msg.Usage.InputTokens,
		"outputTokens", msg.Usage.OutputTokens)

	c.metrics.RecordClaudeUsage(c.source, "all", model,
		int(msg.Usage.InputTokens), int(msg.Usage.OutputTokens),
		int(msg.Usage.CacheCreationInputTokens), int(msg.Usage.CacheReadInputTokens))

	if msg.StopReason != "" && msg.StopReason != anthropic.StopReasonEndTurn {
		slog.Warn("analysis response may be truncated",
			"stop_reason", string(msg.StopReason),
			"model", model,
			"outputTokens", msg.Usage.OutputTokens)
	}

	return extractText(msg), nil
}

// appendToolResultsAndCacheTail appends a user message containing the tool_result
// blocks for the round, marking the last tool_result with cache_control to keep
// a sliding cache breakpoint at the growing tool-output tail.
func appendToolResultsAndCacheTail(messages []anthropic.MessageParam, results []anthropic.ContentBlockParamUnion) []anthropic.MessageParam {
	if len(results) == 0 {
		return messages
	}
	// Mark the last tool_result block with a cache_control breakpoint.
	last := &results[len(results)-1]
	if last.OfToolResult != nil {
		// Copy to avoid mutating the caller's slice element.
		trCopy := *last.OfToolResult
		trCopy.CacheControl = anthropic.NewCacheControlEphemeralParam()
		last.OfToolResult = &trCopy
	}
	return append(messages, anthropic.MessageParam{
		Role:    anthropic.MessageParamRoleUser,
		Content: results,
	})
}

// RunToolLoop runs a multi-turn Claude conversation with tool use.
// handleTool is called for each tool_use block. After maxRounds of tool calls,
// a final request without tools forces Claude to produce a text response.
//
// maxRounds must be at least 1; passing 0 or negative returns an error
// immediately.
func (c *ClaudeClient) RunToolLoop(
	ctx context.Context,
	model string,
	systemPrompt string,
	userPrompt string,
	tools []anthropic.ToolUnionParam,
	maxRounds int,
	handleTool func(name string, input json.RawMessage) (string, error),
) (string, int, bool, error) {
	if model == "" {
		model = c.Model
	}
	if maxRounds <= 0 {
		return "", 0, false, fmt.Errorf("maxRounds must be at least 1, got %d", maxRounds)
	}

	messages := []anthropic.MessageParam{
		anthropic.NewUserMessage(anthropic.NewTextBlock(userPrompt)),
	}

	var totalInput, totalOutput, totalCacheCreation, totalCacheRead int64

	for round := range maxRounds {
		slog.Info("tool loop round", "round", round+1, "maxRounds", maxRounds)

		msg, err := c.sdk.Messages.New(ctx, anthropic.MessageNewParams{
			Model:     anthropic.Model(model),
			MaxTokens: 4096,
			System:    systemBlocks(systemPrompt),
			Tools:     toolsWithCachedTail(tools),
			Messages:  messages,
		})
		if err != nil {
			return "", round + 1, false, fmt.Errorf("round %d: %w", round+1, err)
		}

		totalInput += msg.Usage.InputTokens
		totalOutput += msg.Usage.OutputTokens
		totalCacheCreation += msg.Usage.CacheCreationInputTokens
		totalCacheRead += msg.Usage.CacheReadInputTokens

		// Append the assistant message to the conversation for the next round.
		messages = append(messages, msg.ToParam())

		if msg.StopReason == anthropic.StopReasonEndTurn {
			slog.Info("tool loop complete",
				"rounds", round+1,
				"totalInputTokens", totalInput,
				"totalOutputTokens", totalOutput)
			c.recordTotals(model, totalInput, totalOutput, totalCacheCreation, totalCacheRead)
			return extractText(msg), round + 1, false, nil
		}

		// Process tool_use blocks.
		var toolResults []anthropic.ContentBlockParamUnion
		for _, block := range msg.Content {
			tu, ok := block.AsAny().(anthropic.ToolUseBlock)
			if !ok {
				continue
			}
			slog.Info("tool call", "round", round+1, "tool", tu.Name, "id", tu.ID)
			output, err := handleTool(tu.Name, tu.Input)
			isError := false
			if err != nil {
				output = fmt.Sprintf("error: %v", err)
				isError = true
			}
			toolResults = append(toolResults, anthropic.NewToolResultBlock(tu.ID, output, isError))
		}

		// No tool_use blocks: treat as final answer (covers stop_reason=max_tokens).
		if len(toolResults) == 0 {
			slog.Warn("tool loop: no tool_use blocks found, returning text as final answer",
				"stop_reason", string(msg.StopReason), "round", round+1)
			c.recordTotals(model, totalInput, totalOutput, totalCacheCreation, totalCacheRead)
			return extractText(msg), round + 1, false, nil
		}

		messages = appendToolResultsAndCacheTail(messages, toolResults)
	}

	// Max rounds reached — append the summary text to the last user message
	// (which holds the final round's tool_result blocks) so we don't break the
	// "roles must alternate" invariant.
	slog.Info("tool loop max rounds reached, requesting summary", "maxRounds", maxRounds)

	const summaryPrompt = "You have reached the maximum number of diagnostic rounds. Do NOT call any more tools. Provide your final analysis now based on all information gathered so far. Start directly with the analysis — no preamble or meta-commentary."

	if err := appendTextToLastUserMessage(messages, summaryPrompt); err != nil {
		return "", maxRounds, true, err
	}

	msg, err := c.sdk.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(model),
		MaxTokens: 4096,
		System:    systemBlocks(systemPrompt),
		Tools:     toolsWithCachedTail(tools),
		ToolChoice: anthropic.ToolChoiceUnionParam{
			OfNone: &anthropic.ToolChoiceNoneParam{},
		},
		Messages: messages,
	})
	if err != nil {
		return "", maxRounds, true, fmt.Errorf("summary: %w", err)
	}

	totalInput += msg.Usage.InputTokens
	totalOutput += msg.Usage.OutputTokens
	totalCacheCreation += msg.Usage.CacheCreationInputTokens
	totalCacheRead += msg.Usage.CacheReadInputTokens

	analysis := extractText(msg)
	slog.Info("tool loop complete (forced summary)",
		"totalRounds", maxRounds,
		"totalInputTokens", totalInput,
		"totalOutputTokens", totalOutput,
		"analysisLen", len(analysis))
	if len(analysis) == 0 {
		slog.Warn("forced summary produced empty analysis", "contentBlocks", len(msg.Content))
	}

	c.recordTotals(model, totalInput, totalOutput, totalCacheCreation, totalCacheRead)
	return analysis, maxRounds, true, nil
}

// appendTextToLastUserMessage appends a text block to the last message,
// asserting it is a user role with a content-block slice. Returns an error if
// the loop invariant is violated (which can only happen when maxRounds <= 0,
// caught upstream).
func appendTextToLastUserMessage(messages []anthropic.MessageParam, text string) error {
	if len(messages) == 0 {
		return errors.New("internal: messages slice is empty when appending forced-summary text")
	}
	last := &messages[len(messages)-1]
	if last.Role != anthropic.MessageParamRoleUser {
		return fmt.Errorf("internal: last message role is %q, expected user", string(last.Role))
	}
	last.Content = append(last.Content, anthropic.NewTextBlock(text))
	return nil
}

func (c *ClaudeClient) recordTotals(model string, in, out, cacheCreate, cacheRead int64) {
	c.metrics.RecordClaudeUsage(c.source, "all", model,
		int(in), int(out), int(cacheCreate), int(cacheRead))
}
```

Note on SDK API correctness: `msg.ToParam()` is the canonical SDK helper for converting a returned `*anthropic.Message` (assistant role) into a `MessageParam` for the next request. `anthropic.NewToolResultBlock(id, content, isError)` is the helper for tool-result content blocks. If either helper has a different name in your SDK version, find the equivalent (look in the SDK's tool-use example) and adjust.

### Step 5.F — Migrate `internal/shared/claude_test.go`

This step has many micro-edits. The strategy: keep all existing `httptest.Server`-based tests, swap the client construction from `&ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, ...}` to `NewClaudeClient(BaseConfig{APIBaseURL: srv.URL, APIKey: ..., ClaudeModel: ...}, srv.Client().Transport)`, drop the four obsolete tests, rewrite the typed-error tests, and add the three new auth-header tests.

- [ ] **5.F.1: Add a test helper at the top of `internal/shared/claude_test.go`**

Replace the imports block in `internal/shared/claude_test.go` with:

```go
package shared

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)
```

Then add this helper just below the imports:

```go
// newTestClient returns a ClaudeClient pointed at srv. retries=0 disables SDK
// retries so non-2xx tests do not balloon the request count.
func newTestClient(t *testing.T, srv *httptest.Server, model, apiKey string, retries int) *ClaudeClient {
	t.Helper()
	transport := srv.Client().Transport
	httpClient := &http.Client{Timeout: 30 * time.Second, Transport: transport}
	sdk := anthropic.NewClient(
		option.WithHTTPClient(httpClient),
		option.WithBaseURL(srv.URL),
		option.WithAPIKey(apiKey),
		option.WithAuthToken(""),
		option.WithMaxRetries(retries),
	)
	return &ClaudeClient{sdk: &sdk, Model: model}
}
```

This helper is the migration shim for tests that previously did `client := &ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "test-key", Model: "test"}`. Each such construction is replaced with `client := newTestClient(t, srv, "test", "test-key", 0)`.

- [ ] **5.F.2: Delete the four obsolete tests**

Delete the entire function bodies (and their preceding doc comments) for:
- `TestAnalyze_APIErrorInBody`
- `TestRunToolLoop_APIErrorInBody`
- `TestRunToolLoop_SummaryAPIErrorInBody`
- `TestSendRequest_MarshalFailure`

These are the only tests dropped by this migration; rationale is in the spec ("200-OK with embedded error" subsection).

- [ ] **5.F.3: Move three transport-layer tests OUT of this file**

The following tests were already migrated to `transport_test.go` in Task 4. Delete them here:
- `TestSendRequest_OversizedResponseIsBounded`
- `TestSendRequest_DurationHistogramObservedOnSuccess`
- `TestSendRequest_DurationHistogramObservedOnNonOK`

- [ ] **5.F.4: Rename and rewrite `TestSendRequest_RetriesOnTransientError` and `TestSendRequest_NoRetryOnClientError`**

Replace these two functions with:

```go
func TestClaudeClient_RetriesOnTransientError(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, "temporarily unavailable")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)
	}))
	defer srv.Close()

	c := newTestClient(t, srv, "test-model", "test-key", 2)
	result, err := c.Analyze(context.Background(), "test-model", "sys", "user")
	if err != nil {
		t.Fatalf("expected success after retries, got: %v", err)
	}
	if result != "ok" {
		t.Errorf("expected %q, got %q", "ok", result)
	}
	if n := calls.Load(); n != 3 {
		t.Errorf("expected 3 attempts (1 initial + 2 retries), got %d", n)
	}
}

func TestClaudeClient_NoRetryOnClientError(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"type":"error","error":{"type":"invalid_request_error","message":"bad"}}`)
	}))
	defer srv.Close()

	c := newTestClient(t, srv, "test-model", "test-key", 2)
	_, err := c.Analyze(context.Background(), "test-model", "sys", "user")
	if err == nil {
		t.Fatal("expected error for 400 response")
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("expected exactly 1 attempt for non-transient error, got %d", n)
	}
}
```

- [ ] **5.F.5: Rewrite `TestAnalyze_HTTPError`**

Replace its body with:

```go
func TestAnalyze_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"type":"error","error":{"type":"rate_limit_error","message":"too many"}}`)
	}))
	defer srv.Close()

	c := newTestClient(t, srv, "test-model", "test-key", 0)
	_, err := c.Analyze(context.Background(), "test-model", "sys", "user")
	if err == nil {
		t.Fatal("expected error for 429 response")
	}
	var apiErr *anthropic.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *anthropic.Error, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusTooManyRequests {
		t.Errorf("expected StatusCode=429, got %d", apiErr.StatusCode)
	}
}
```

- [ ] **5.F.6: Rewrite `TestAnalyze_ParseResponseError`**

Replace its body with:

```go
func TestAnalyze_ParseResponseError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<!DOCTYPE html><html><body>Service Unavailable</body></html>`)
	}))
	defer srv.Close()

	c := newTestClient(t, srv, "test-model", "test-key", 0)
	_, err := c.Analyze(context.Background(), "test-model", "sys", "user")
	if err == nil {
		t.Fatal("expected error when API returns non-JSON body")
	}
	// SDK error type may vary across versions; assert non-nil and that the
	// error message is non-empty rather than pinning to a specific substring.
	if err.Error() == "" {
		t.Error("expected non-empty error message")
	}
}
```

- [ ] **5.F.7: Rewrite `TestRunToolLoop_SummaryParseFailure`**

Replace its body with:

```go
func TestRunToolLoop_SummaryParseFailure(t *testing.T) {
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		call := callCount.Add(1)
		if call == 1 {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{
				"content": [{"type": "tool_use", "id": "toolu_1", "name": "execute_command", "input": {"command": ["uptime"]}}],
				"stop_reason": "tool_use",
				"usage": {"input_tokens": 50, "output_tokens": 10}
			}`)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><body>Service Unavailable</body>`)
	}))
	defer srv.Close()

	c := newTestClient(t, srv, "test-model", "test-key", 0)
	tools := []anthropic.ToolUnionParam{{
		OfTool: &anthropic.ToolParam{
			Name: "execute_command", Description: anthropic.String("test"),
			InputSchema: anthropic.ToolInputSchemaParam{Properties: map[string]any{}},
		},
	}}

	_, _, _, err := c.RunToolLoop(context.Background(), "test-model", "system", "user", tools, 1,
		func(_ string, _ json.RawMessage) (string, error) { return "load: 0.1", nil })
	if err == nil {
		t.Fatal("expected error when summary response is not valid JSON")
	}
	if !strings.Contains(err.Error(), "summary") {
		t.Errorf("error should mention 'summary', got: %v", err)
	}
}
```

- [ ] **5.F.8: Replace `TestSendRequest_AlwaysUsesXAPIKey` with three new auth-header tests**

Delete the old `TestSendRequest_AlwaysUsesXAPIKey` function entirely. Add these three:

```go
func TestNewClaudeClient_APIKeyHeader(t *testing.T) {
	var gotKey, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer srv.Close()

	c := NewClaudeClient(BaseConfig{
		APIKey:      "tok",
		APIBaseURL:  srv.URL,
		ClaudeModel: "m",
	}, srv.Client().Transport)
	if _, err := c.Analyze(context.Background(), "m", "s", "u"); err != nil {
		t.Fatal(err)
	}
	if gotKey != "tok" {
		t.Errorf("x-api-key: got %q, want tok", gotKey)
	}
	if gotAuth != "" {
		t.Errorf("Authorization should be empty when only APIKey is set, got %q", gotAuth)
	}
}

func TestNewClaudeClient_AuthTokenHeader(t *testing.T) {
	var gotKey, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer srv.Close()

	c := NewClaudeClient(BaseConfig{
		AuthToken:   "bearer-tok",
		APIBaseURL:  srv.URL,
		ClaudeModel: "m",
	}, srv.Client().Transport)
	if _, err := c.Analyze(context.Background(), "m", "s", "u"); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer bearer-tok" {
		t.Errorf("Authorization: got %q, want %q", gotAuth, "Bearer bearer-tok")
	}
	if gotKey != "" {
		t.Errorf("x-api-key should be empty when only AuthToken is set, got %q", gotKey)
	}
}

func TestNewClaudeClient_AnthropicVersionHeader(t *testing.T) {
	var gotVersion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotVersion = r.Header.Get("anthropic-version")
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer srv.Close()

	c := NewClaudeClient(BaseConfig{
		APIKey:      "tok",
		APIBaseURL:  srv.URL,
		ClaudeModel: "m",
	}, srv.Client().Transport)
	if _, err := c.Analyze(context.Background(), "m", "s", "u"); err != nil {
		t.Fatal(err)
	}
	if gotVersion == "" {
		t.Error("expected non-empty anthropic-version header from SDK")
	}
}
```

- [ ] **5.F.9: Update every other `&ClaudeClient{...}` construction to use `newTestClient`**

Run:
```bash
grep -n '&ClaudeClient{' internal/shared/claude_test.go
```
For each match, replace the construction with the appropriate `newTestClient(t, srv, "test-model", "test-key", 0)` (use `0` for retries unless the test specifically exercises retry behavior).

For tests that today set `c.retryDelays = []time.Duration{}`, simply pass `0` retries to `newTestClient` and remove the `c.retryDelays` assignment.

- [ ] **5.F.10: Replace `[]Tool{...}` literals in this test file with `[]anthropic.ToolUnionParam{...}`**

Run:
```bash
grep -n '\[\]Tool{' internal/shared/claude_test.go
```
For each tool literal, rewrite using the SDK shape:
```go
tools := []anthropic.ToolUnionParam{{
    OfTool: &anthropic.ToolParam{
        Name: "...", Description: anthropic.String("..."),
        InputSchema: anthropic.ToolInputSchemaParam{Properties: map[string]any{}},
    },
}}
```
(For multiple tools, repeat the union element.)

### Step 5.G — Delete `internal/shared/types.go`

- [ ] **5.G.1: Delete the file**

```bash
rm internal/shared/types.go
```

### Step 5.H — Build, test, commit

- [ ] **5.H.1: Verify the codebase builds**

Run: `CGO_ENABLED=0 go build ./...`
Expected: success.

If the build fails with references to `shared.Tool`, `shared.ContentBlock`, `shared.ToolMessage`, `shared.SystemBlock`, `shared.CacheControl`, `shared.ToolRequest`, or `shared.ToolResponse`, locate the offending file and update it to the SDK type or test-mock equivalent. Track outstanding issues with:
```bash
grep -rn 'shared\.\(Tool\|ContentBlock\|ToolMessage\|SystemBlock\|CacheControl\|ToolRequest\|ToolResponse\)\b' internal/ cmd/
```

- [ ] **5.H.2: Run all tests**

Run: `go test ./...`
Expected: all tests pass.

- [ ] **5.H.3: Run with `-race`**

Run: `go test ./... -race`
Expected: all tests pass, no race warnings.

- [ ] **5.H.4: Commit**

```bash
git add -A
git commit -m "refactor(shared): switch ClaudeClient to anthropic-sdk-go

Drops hand-rolled internal/shared/types.go and ~290 lines of HTTP plumbing
in claude.go. Tool types throughout the codebase are now anthropic.ToolUnionParam.
ToolLoopRunner.RunToolLoop signature changes accordingly; pipeline
orchestration code is unchanged.

Behavior preserved at the public-API level:
- 3-breakpoint prompt caching (system, last tool, last tool_result)
- Atomic per-analysis token recording
- Forced-summary turn with tool_choice: none
- Body cap and latency histogram via LimitedTransport (added in prior commit)

Tests:
- 4 dropped tests covering the 200-OK-with-embedded-error shape (rationale
  in docs/superpowers/specs/2026-05-02-anthropic-sdk-migration-design.md)
- 1 dropped test for marshal failure (no longer reachable)
- 3 new auth-header tests (x-api-key, Authorization Bearer, anthropic-version)
"
```

---

## Task 6: Wire `cmd/k8s-analyzer/main.go` to SDK env vars and transport

**Files:**
- Modify: `cmd/k8s-analyzer/main.go`

- [ ] **Step 1: Replace `loadConfig` env-var reads**

In `cmd/k8s-analyzer/main.go`, replace the existing `loadConfig` function with:

```go
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
	webhookSecret, err := shared.RequireEnv("WEBHOOK_SECRET")
	if err != nil {
		slog.Error("config error", "error", err)
		os.Exit(1)
	}

	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	authToken := os.Getenv("ANTHROPIC_AUTH_TOKEN")
	baseURL := os.Getenv("ANTHROPIC_BASE_URL")

	switch {
	case apiKey == "" && authToken == "":
		slog.Error("config error", "error", "either ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN must be set")
		os.Exit(1)
	case apiKey != "" && authToken != "":
		slog.Error("config error", "error", "set exactly one of ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN, not both")
		os.Exit(1)
	}

	// Unset the three vars so the SDK never falls back to its own env-var
	// lookups; main.go is the single source of truth.
	os.Unsetenv("ANTHROPIC_API_KEY")
	os.Unsetenv("ANTHROPIC_AUTH_TOKEN")
	os.Unsetenv("ANTHROPIC_BASE_URL")

	return k8s.Config{
		PrometheusURL:   shared.EnvOrDefault("PROMETHEUS_URL", "http://kube-prometheus-stack-prometheus.monitoring.svc.cluster.local:9090"),
		ClaudeModel:     shared.EnvOrDefault("CLAUDE_MODEL", "claude-sonnet-4-6"),
		CooldownSeconds: cooldown,
		SkipResolved:    shared.EnvOrDefault("SKIP_RESOLVED", "true") != "false",
		Port:            shared.EnvOrDefault("PORT", "8080"),
		MetricsPort:     shared.EnvOrDefault("METRICS_PORT", "9101"),
		WebhookSecret:   webhookSecret,
		MaxLogBytes:     maxLogBytes,
		APIBaseURL:      baseURL,
		APIKey:          apiKey,
		AuthToken:       authToken,
	}
}
```

- [ ] **Step 2: Update the `claudeClient` construction in `main()`**

Replace the line:
```go
claudeClient := shared.NewClaudeClient(cfg.BaseConfig()).WithPrometheusMetrics(metrics, "k8s")
```
with:
```go
hist := metrics.Prom.ClaudeAPIDuration.WithLabelValues("k8s")
transport := shared.NewLimitedTransport(http.DefaultTransport, hist)
claudeClient := shared.NewClaudeClient(cfg.BaseConfig(), transport).WithPrometheusMetrics(metrics, "k8s")
```

- [ ] **Step 3: Add `"net/http"` to the imports**

Add `"net/http"` to the imports block of `cmd/k8s-analyzer/main.go`.

- [ ] **Step 4: Verify build**

Run: `CGO_ENABLED=0 go build ./cmd/k8s-analyzer/`
Expected: success.

- [ ] **Step 5: Verify tests**

Run: `go test ./...`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add cmd/k8s-analyzer/main.go
git commit -m "feat(k8s)!: switch to ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN / ANTHROPIC_BASE_URL

Breaking change: API_KEY and API_BASE_URL env vars are removed.
Set exactly one of ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN at startup;
both-set or neither-set fails fast.

The three ANTHROPIC_* env vars are unset after reading so the SDK never
falls back to them. Latency histogram is now wired through the new
LimitedTransport.
"
```

---

## Task 7: Wire `cmd/checkmk-analyzer/main.go` to SDK env vars and transport

**Files:**
- Modify: `cmd/checkmk-analyzer/main.go`

- [ ] **Step 1: Replace the auth-related parts of `loadConfig`**

In `cmd/checkmk-analyzer/main.go`, find the existing `apiKey, err := shared.RequireEnv("API_KEY")` block (lines 26–30) and the `APIBaseURL: shared.EnvOrDefault("API_BASE_URL", ...)` line in the returned struct.

Replace the auth-related lines with the same logic used in Task 6:

```go
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	authToken := os.Getenv("ANTHROPIC_AUTH_TOKEN")
	baseURL := os.Getenv("ANTHROPIC_BASE_URL")

	switch {
	case apiKey == "" && authToken == "":
		slog.Error("config error", "error", "either ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN must be set")
		os.Exit(1)
	case apiKey != "" && authToken != "":
		slog.Error("config error", "error", "set exactly one of ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN, not both")
		os.Exit(1)
	}

	os.Unsetenv("ANTHROPIC_API_KEY")
	os.Unsetenv("ANTHROPIC_AUTH_TOKEN")
	os.Unsetenv("ANTHROPIC_BASE_URL")
```

In the returned `checkmk.Config{...}` literal, replace:
```go
APIBaseURL: shared.EnvOrDefault("API_BASE_URL", "https://api.anthropic.com/v1/messages"),
APIKey:     apiKey,
```
with:
```go
APIBaseURL: baseURL,
APIKey:     apiKey,
AuthToken:  authToken,
```

- [ ] **Step 2: Update the `claudeClient` construction in `main()`**

Replace:
```go
claudeClient := shared.NewClaudeClient(cfg.BaseConfig()).WithPrometheusMetrics(metrics, "checkmk")
```
with:
```go
hist := metrics.Prom.ClaudeAPIDuration.WithLabelValues("checkmk")
transport := shared.NewLimitedTransport(http.DefaultTransport, hist)
claudeClient := shared.NewClaudeClient(cfg.BaseConfig(), transport).WithPrometheusMetrics(metrics, "checkmk")
```

- [ ] **Step 3: Add `"net/http"` to imports**

Add `"net/http"` to the imports block.

- [ ] **Step 4: Verify build**

Run: `CGO_ENABLED=0 go build ./cmd/checkmk-analyzer/`
Expected: success.

- [ ] **Step 5: Verify tests**

Run: `go test ./...`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add cmd/checkmk-analyzer/main.go
git commit -m "feat(checkmk)!: switch to ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN / ANTHROPIC_BASE_URL

Same hard cut as for the k8s analyzer.
"
```

---

## Task 8: Add startup-auth-validation tests for both binaries

**Files:**
- Create: `cmd/k8s-analyzer/main_test.go`
- Create: `cmd/checkmk-analyzer/main_test.go`

Because `loadConfig` calls `os.Exit(1)` directly on misconfiguration, the tests run the compiled binary as a subprocess and assert the exit code + stderr.

- [ ] **Step 1: Create `cmd/k8s-analyzer/main_test.go`**

```go
package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// runMainWithEnv builds and runs the k8s-analyzer binary with the given env
// vars and returns its exit code + stderr. The build is cached by `go test`.
func runMainWithEnv(t *testing.T, env map[string]string) (int, string) {
	t.Helper()

	binary := buildBinary(t)
	cmd := exec.Command(binary)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	exit := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		} else {
			t.Fatalf("unexpected error type: %v", err)
		}
	}
	return exit, string(out)
}

func buildBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := dir + "/k8s-analyzer"
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	return bin
}

func TestMain_FailsWhenBothAuthVarsSet(t *testing.T) {
	exit, stderr := runMainWithEnv(t, map[string]string{
		"ANTHROPIC_API_KEY":    "x",
		"ANTHROPIC_AUTH_TOKEN": "y",
		"WEBHOOK_SECRET":       "secret",
	})
	if exit == 0 {
		t.Fatalf("expected non-zero exit when both auth vars are set; stderr=%s", stderr)
	}
	if !strings.Contains(stderr, "set exactly one") {
		t.Errorf("expected 'set exactly one' in stderr, got: %s", stderr)
	}
}

func TestMain_FailsWhenNeitherAuthVarSet(t *testing.T) {
	exit, stderr := runMainWithEnv(t, map[string]string{
		"WEBHOOK_SECRET": "secret",
	})
	if exit == 0 {
		t.Fatalf("expected non-zero exit when neither auth var is set; stderr=%s", stderr)
	}
	if !strings.Contains(stderr, "must be set") {
		t.Errorf("expected 'must be set' in stderr, got: %s", stderr)
	}
}
```

Note: `TestMain_FailsWhenNeitherAuthVarSet` and `..._BothAuthVarsSet` exit before reaching the `rest.InClusterConfig()` call. They do not need k8s API access and run cleanly outside a cluster. If your local environment exposes ANTHROPIC_* env vars by default, prefix the test invocation with `env -i` or unset them in the test runner.

- [ ] **Step 2: Run the new tests**

Run: `go test ./cmd/k8s-analyzer/ -v -run TestMain_`
Expected: 2 PASS.

- [ ] **Step 3: Create `cmd/checkmk-analyzer/main_test.go`**

Same content as Step 1 but with:
- `binary := dir + "/checkmk-analyzer"` instead of `k8s-analyzer`
- The minimal env in each test must additionally include `CHECKMK_API_USER=u`, `CHECKMK_API_SECRET=s` so `loadConfig` reaches the auth-validation switch (these are required by the binary).

```go
package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func runMainWithEnv(t *testing.T, env map[string]string) (int, string) {
	t.Helper()

	binary := buildBinary(t)
	cmd := exec.Command(binary)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	exit := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		} else {
			t.Fatalf("unexpected error type: %v", err)
		}
	}
	return exit, string(out)
}

func buildBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := dir + "/checkmk-analyzer"
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	return bin
}

func minEnv() map[string]string {
	return map[string]string{
		"WEBHOOK_SECRET":     "secret",
		"CHECKMK_API_USER":   "u",
		"CHECKMK_API_SECRET": "s",
	}
}

func TestMain_FailsWhenBothAuthVarsSet(t *testing.T) {
	env := minEnv()
	env["ANTHROPIC_API_KEY"] = "x"
	env["ANTHROPIC_AUTH_TOKEN"] = "y"
	exit, stderr := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit when both auth vars are set; stderr=%s", stderr)
	}
	if !strings.Contains(stderr, "set exactly one") {
		t.Errorf("expected 'set exactly one' in stderr, got: %s", stderr)
	}
}

func TestMain_FailsWhenNeitherAuthVarSet(t *testing.T) {
	exit, stderr := runMainWithEnv(t, minEnv())
	if exit == 0 {
		t.Fatalf("expected non-zero exit when neither auth var is set; stderr=%s", stderr)
	}
	if !strings.Contains(stderr, "must be set") {
		t.Errorf("expected 'must be set' in stderr, got: %s", stderr)
	}
}
```

- [ ] **Step 4: Run the new tests**

Run: `go test ./cmd/checkmk-analyzer/ -v -run TestMain_`
Expected: 2 PASS.

- [ ] **Step 5: Run the full suite once more**

Run: `go test ./... -race`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add cmd/k8s-analyzer/main_test.go cmd/checkmk-analyzer/main_test.go
git commit -m "test(cmd): startup auth-validation tests for both binaries"
```

---

## Task 9: Update documentation

**Files:**
- Modify: `docs/cost-and-storm-protection.md`
- Modify: `CLAUDE.md`
- Modify: `README.md`

- [ ] **Step 1: Update `docs/cost-and-storm-protection.md`**

Find the section that says "OpenRouter compatibility deferred" or similar (search: `grep -n 'OpenRouter\|deferred' docs/cost-and-storm-protection.md`). Remove that paragraph. Replace it with a new "OpenRouter setup" section:

```markdown
## OpenRouter Setup

The `anthropic-sdk-go` migration restored OpenRouter compatibility. To route via OpenRouter:

```sh
export ANTHROPIC_BASE_URL=https://openrouter.ai/api
export ANTHROPIC_AUTH_TOKEN=sk-or-v1-...
unset ANTHROPIC_API_KEY  # only one of API_KEY / AUTH_TOKEN may be set
```

The SDK uses `Authorization: Bearer $ANTHROPIC_AUTH_TOKEN` against this base URL, which is OpenRouter's expected auth shape.
```

- [ ] **Step 2: Update `CLAUDE.md`**

Run: `grep -n 'OpenRouter\|API_KEY\|API_BASE_URL\|Authorization: Bearer\|Bearer-Auth' CLAUDE.md`

For each match:
- If it documents the now-removed deferral ("OpenRouter compatibility is deferred to a planned follow-up that migrates the client to anthropic-sdk-go"), delete that paragraph.
- If it references `API_KEY` or `API_BASE_URL` as canonical env vars, update to `ANTHROPIC_API_KEY` / `ANTHROPIC_BASE_URL`.

Add to the architecture description (search for "Claude API client" — likely under "Key Design Patterns"):

> The Claude API client wraps `github.com/anthropics/anthropic-sdk-go` with a `LimitedTransport` for body capping and latency observation. Auth is configured via `ANTHROPIC_API_KEY` (sets `x-api-key`) or `ANTHROPIC_AUTH_TOKEN` (sets `Authorization: Bearer`); exactly one of the two must be set. Setting both at startup is a fatal error.

- [ ] **Step 3: Update `README.md`**

Run: `grep -n 'API_KEY\|API_BASE_URL\|OpenRouter\|LLM provider' README.md`

In the "LLM provider" section, replace the "OpenRouter not supported" text with:

```markdown
### LLM provider

The analyzer talks to the Anthropic Messages API via the official `anthropic-sdk-go` client. Configure the auth method via env vars:

- `ANTHROPIC_API_KEY` — sets `x-api-key` header (Anthropic's native scheme)
- `ANTHROPIC_AUTH_TOKEN` — sets `Authorization: Bearer` header (required for OpenRouter)
- `ANTHROPIC_BASE_URL` — optional; default is the Anthropic API. Set to `https://openrouter.ai/api` for OpenRouter.

Exactly one of `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN` must be set at startup.
```

- [ ] **Step 4: Verify the spec links still resolve**

Run:
```bash
grep -rn 'docs/superpowers/specs/2026-05-02-anthropic-sdk-migration-design.md' docs/ CLAUDE.md README.md 2>/dev/null
```
If your final docs reference the spec by path, verify the path is correct.

- [ ] **Step 5: Commit**

```bash
git add docs/cost-and-storm-protection.md CLAUDE.md README.md
git commit -m "docs: document anthropic-sdk-go migration and OpenRouter setup"
```

---

## Task 10: Acceptance-gate verification

**Files:** None — only verifications.

This task runs the acceptance gates listed in the spec. If any fail, fix before declaring the migration complete.

- [ ] **Step 1: Build & test gates**

```bash
CGO_ENABLED=0 go build ./cmd/k8s-analyzer/
CGO_ENABLED=0 go build ./cmd/checkmk-analyzer/
go test ./... -race
grep 'anthropics/anthropic-sdk-go' go.mod
```
Expected: all succeed; `go.mod` shows the SDK as a direct dependency.

- [ ] **Step 2: Public-API contract gate**

```bash
git diff main -- internal/k8s/pipeline.go internal/checkmk/pipeline.go
```
Expected: empty output (pipeline files untouched). If your branch is named differently, replace `main` with your base branch.

- [ ] **Step 3: Code-volume gate**

```bash
wc -l internal/shared/claude.go
```
Expected: a number between 100 and 200 (target ~150; today ~440). If higher than 200, look for opportunities to delete dead helpers.

- [ ] **Step 4: No-translation-layer gate**

```bash
grep -rn 'shared\.Tool\b\|shared\.ContentBlock\|shared\.ToolMessage\|shared\.SystemBlock\|shared\.CacheControl\|shared\.ToolRequest\|shared\.ToolResponse' internal/ cmd/
```
Expected: 0 matches.

- [ ] **Step 5: Phase-2-isolation gate**

```bash
grep -nE 'CircuitBreaker|StormDetector|GroupCooldown|ErrCircuitOpen|IsHalfOpenProbe|IsDegraded' internal/shared/claude.go internal/shared/transport.go internal/shared/payload.go cmd/k8s-analyzer/main.go cmd/checkmk-analyzer/main.go
```
Expected: 0 matches. (`internal/shared/policy.go` may contain these terms — Phase-1 reservation, not in scope here.)

- [ ] **Step 6: Streaming-isolation gate**

```bash
grep -nE 'NewStreaming|MessagesStreaming|StreamingMessage|MessageStream\b' internal/shared/claude.go internal/shared/transport.go
```
Expected: 0 matches.

- [ ] **Step 7: Empty-analysis pipeline failure gate**

This requires a small integration test against the existing pipeline — Codex confirmed `internal/k8s/pipeline_test.go:345` and `internal/checkmk/pipeline_test.go:482` already cover empty-result paths from the tool-loop side. Verify that the Analyzer-path empty-result case is also covered:

```bash
grep -n 'analysis returned empty result\|return "", nil' internal/k8s/pipeline_test.go internal/checkmk/pipeline_test.go
```

If the Analyzer-path empty-result case is not yet tested, add a minimal test in `internal/k8s/pipeline_test.go` that drives an `Analyzer` mock returning `("", nil)` and asserts: `slog` warns "analysis returned empty result", a publish call is made with priority `"5"` and title prefix `Analysis FAILED:`, `Cooldown.Clear` is called for the fingerprint, and `Metrics.AlertsFailed` is incremented. Mirror the assertion shape used in the existing empty-result tool-loop test at `internal/k8s/pipeline_test.go:345`.

Then commit:

```bash
git add internal/k8s/pipeline_test.go internal/checkmk/pipeline_test.go
git commit -m "test(pipeline): verify Analyzer-path empty-result path triggers failure ntfy"
```

(Skip the commit if the two greps already showed coverage.)

- [ ] **Step 8: OpenRouter smoke test (manual)**

This is a deployment-time gate, not a unit test. In a staging cluster, deploy the new image with:
```yaml
env:
  - name: ANTHROPIC_BASE_URL
    value: https://openrouter.ai/api
  - name: ANTHROPIC_AUTH_TOKEN
    value: sk-or-v1-...
```
Send a test webhook and confirm a successful analysis lands in ntfy.

If you cannot run this manually right now, document the result (PASS/FAIL/DEFERRED) in the PR description.

- [ ] **Step 9: Final commit-hygiene check**

Confirm at least one commit on the branch carries the `feat!:` prefix. Run:
```bash
git log --oneline main..HEAD | grep '^[a-f0-9]\+ feat!:'
```
Expected: at least one match (Tasks 6 and 7 both qualify).

---

## Summary of commits this plan produces

1. `chore(deps): add anthropic-sdk-go for SDK migration`
2. `refactor(shared): extract non-tool types into payload.go`
3. `refactor(config): add AuthToken field, plumbed through k8s and checkmk Config`
4. `feat(shared): add LimitedTransport for body cap and latency histogram`
5. `refactor(shared): switch ClaudeClient to anthropic-sdk-go` (the big refactor)
6. `feat(k8s)!: switch to ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN / ANTHROPIC_BASE_URL`
7. `feat(checkmk)!: switch to ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN / ANTHROPIC_BASE_URL`
8. `test(cmd): startup auth-validation tests for both binaries`
9. `docs: document anthropic-sdk-go migration and OpenRouter setup`
10. (optional) `test(pipeline): verify Analyzer-path empty-result path triggers failure ntfy`
