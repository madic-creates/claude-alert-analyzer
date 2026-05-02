# Storm/Cost Protection — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce Claude-API token costs through prompt caching, severity-based model/rounds routing, and a cost-visibility metric layer. Drop OpenRouter URL branching (breaking change).

**Architecture:** Add a `Severity` enum and `AnalysisPolicy` struct in `internal/shared/`, populated from new optional ENV vars. Both pipelines (`internal/k8s`, `internal/checkmk`) compute severity in their handlers and ask the policy for `model`/`rounds` per alert. `ClaudeClient` is refactored so `Analyze`/`RunToolLoop` take a `model` parameter, and the request body adds `cache_control` breakpoints on three levels (system, tools, tool-loop history). New Prometheus counters track input/output/cache tokens.

**Tech Stack:** Go 1.26, `internal/shared/` testify-style table tests, `prometheus/client_golang`, Anthropic Messages API.

**Spec reference:** `docs/superpowers/specs/2026-05-01-storm-cost-protection-design.md` (Phase 1 sections 1.1–1.5, plus Architecture and Severity-Modell).

**Phase 2** (Group-Cooldown, Storm-Mode, Circuit-Breaker) is intentionally out-of-scope here. A separate plan will be written after Phase 1 ships and metrics are observed.

---

## File Structure (Phase 1)

**New files:**
- `internal/shared/severity.go` — `Severity` enum + `SeverityFromAlertmanager` + `SeverityFromCheckMK`
- `internal/shared/severity_test.go`
- `internal/shared/policy.go` — `AnalysisPolicy` struct with `ModelFor` / `MaxRoundsFor`
- `internal/shared/policy_test.go`

**Modified files:**
- `internal/shared/types.go` — Add `Severity` field to `AlertPayload`; add `SystemBlock`, `CacheControl`, `ToolWithCache` types; change `ToolRequest.System` to `[]SystemBlock`; extend `ToolResponse.Usage` with `CacheCreationInputTokens` + `CacheReadInputTokens`
- `internal/shared/types_test.go`
- `internal/shared/claude.go` — `Analyze`/`RunToolLoop` take a `model string` param; drop URL-conditional auth; build cached System + Tools + tool-loop-history breakpoints; emit cache token metrics
- `internal/shared/claude_test.go`
- `internal/shared/prom_metrics.go` — new counters `claude_input_tokens_total`, `claude_output_tokens_total`, `claude_cache_creation_tokens_total`, `claude_cache_read_tokens_total`
- `internal/shared/metrics.go` — `RecordClaudeUsage` helper
- `internal/shared/metrics_test.go`
- `internal/shared/config.go` — keep `ParseIntEnv`/`EnvOrDefault`/`RequireEnv` unchanged; new helper `LoadPolicy` (in policy.go) reads severity ENV vars
- `internal/k8s/types.go` — add `Policy *shared.AnalysisPolicy` to `PipelineDeps`; remove `MaxAgentRounds` (moves into Policy)
- `internal/k8s/handler.go` — populate `AlertPayload.Severity` via `SeverityFromAlertmanager`
- `internal/k8s/handler_test.go`
- `internal/k8s/pipeline.go` — use `deps.Policy.ModelFor` / `deps.Policy.MaxRoundsFor`; switch to `Analyze` when `rounds == 0`
- `internal/k8s/pipeline_test.go`
- `internal/checkmk/types.go` — add `Policy *shared.AnalysisPolicy` to `PipelineDeps`; remove `MaxAgentRounds`
- `internal/checkmk/handler.go` — populate `AlertPayload.Severity` via `SeverityFromCheckMK`
- `internal/checkmk/handler_test.go`
- `internal/checkmk/pipeline.go` — use Policy; switch to `Analyze` for `rounds == 0`
- `internal/checkmk/pipeline_test.go`
- `cmd/k8s-analyzer/main.go` — call `shared.LoadPolicy`, wire into `PipelineDeps`
- `cmd/checkmk-analyzer/main.go` — same
- `CLAUDE.md` — Phase 1 ENV vars, breaking-change note for OpenRouter

---

## Task 1: Severity enum + normalizers

**Files:**
- Create: `internal/shared/severity.go`
- Create: `internal/shared/severity_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/shared/severity_test.go
package shared

import "testing"

func TestSeverityFromAlertmanager(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
		want   Severity
	}{
		{"critical", map[string]string{"severity": "critical"}, SeverityCritical},
		{"page", map[string]string{"severity": "page"}, SeverityCritical},
		{"warning", map[string]string{"severity": "warning"}, SeverityWarning},
		{"notice", map[string]string{"severity": "notice"}, SeverityWarning},
		{"info", map[string]string{"severity": "info"}, SeverityInfo},
		{"unknown_label_defaults_to_warning", map[string]string{"severity": "weird"}, SeverityWarning},
		{"missing_label_defaults_to_warning", map[string]string{}, SeverityWarning},
		{"case_insensitive", map[string]string{"severity": "CRITICAL"}, SeverityCritical},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SeverityFromAlertmanager(tt.labels); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSeverityFromCheckMK(t *testing.T) {
	tests := []struct {
		name         string
		serviceState string
		hostState    string
		want         Severity
	}{
		{"service_critical", "CRITICAL", "", SeverityCritical},
		{"service_warning", "WARNING", "", SeverityWarning},
		{"service_unknown", "UNKNOWN", "", SeverityWarning},
		{"host_down", "", "DOWN", SeverityCritical},
		{"host_unreachable", "", "UNREACHABLE", SeverityCritical},
		{"host_ok_fallback", "", "UP", SeverityWarning},
		{"empty_both_defaults_to_warning", "", "", SeverityWarning},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SeverityFromCheckMK(tt.serviceState, tt.hostState); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SeverityCritical, "critical"},
		{SeverityWarning, "warning"},
		{SeverityInfo, "info"},
		{SeverityUnknown, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.sev.String(); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/shared/ -run TestSeverity -v`
Expected: FAIL — `SeverityFromAlertmanager`, `SeverityFromCheckMK`, `Severity`, `String` undefined.

- [ ] **Step 3: Implement Severity**

```go
// internal/shared/severity.go
package shared

import "strings"

// Severity is a normalized alert severity used for routing decisions.
type Severity int

const (
	SeverityUnknown Severity = iota
	SeverityInfo
	SeverityWarning
	SeverityCritical
)

// String returns the lowercase string label for the severity.
func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "critical"
	case SeverityWarning:
		return "warning"
	case SeverityInfo:
		return "info"
	default:
		return "unknown"
	}
}

// SeverityFromAlertmanager maps the Alertmanager `severity` label to a Severity.
// Unknown or missing labels default to SeverityWarning (defensive — we'd rather
// pay for an unnecessary analysis than silently downgrade a real critical).
func SeverityFromAlertmanager(labels map[string]string) Severity {
	switch strings.ToLower(labels["severity"]) {
	case "critical", "page":
		return SeverityCritical
	case "warning", "notice":
		return SeverityWarning
	case "info":
		return SeverityInfo
	default:
		return SeverityWarning
	}
}

// SeverityFromCheckMK maps CheckMK service/host state strings to a Severity.
// serviceState takes precedence; hostState is the fallback for host-level
// notifications where serviceState is empty.
func SeverityFromCheckMK(serviceState, hostState string) Severity {
	switch serviceState {
	case "CRITICAL":
		return SeverityCritical
	case "WARNING":
		return SeverityWarning
	case "UNKNOWN":
		return SeverityWarning
	}
	switch hostState {
	case "DOWN", "UNREACHABLE":
		return SeverityCritical
	}
	return SeverityWarning
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/shared/ -run TestSeverity -v`
Expected: PASS for all subtests.

- [ ] **Step 5: Commit**

```bash
git add internal/shared/severity.go internal/shared/severity_test.go
git commit -m "feat(shared): add Severity enum and source-specific normalizers"
```

---

## Task 2: AnalysisPolicy struct

**Files:**
- Create: `internal/shared/policy.go`
- Create: `internal/shared/policy_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/shared/policy_test.go
package shared

import "testing"

func TestAnalysisPolicy_ModelFor(t *testing.T) {
	t.Run("falls_back_to_default_when_no_overrides", func(t *testing.T) {
		p := &AnalysisPolicy{DefaultModel: "claude-sonnet-4-6"}
		for _, sev := range []Severity{SeverityCritical, SeverityWarning, SeverityInfo, SeverityUnknown} {
			if got := p.ModelFor(sev); got != "claude-sonnet-4-6" {
				t.Errorf("severity %v: got %q, want default", sev, got)
			}
		}
	})

	t.Run("uses_override_when_present", func(t *testing.T) {
		p := &AnalysisPolicy{
			DefaultModel: "claude-sonnet-4-6",
			ModelOverrides: map[Severity]string{
				SeverityCritical: "claude-opus-4-7",
				SeverityWarning:  "claude-haiku-4-5",
			},
		}
		if got := p.ModelFor(SeverityCritical); got != "claude-opus-4-7" {
			t.Errorf("critical: got %q, want claude-opus-4-7", got)
		}
		if got := p.ModelFor(SeverityWarning); got != "claude-haiku-4-5" {
			t.Errorf("warning: got %q, want claude-haiku-4-5", got)
		}
		if got := p.ModelFor(SeverityInfo); got != "claude-sonnet-4-6" {
			t.Errorf("info (no override): got %q, want default", got)
		}
	})
}

func TestAnalysisPolicy_MaxRoundsFor(t *testing.T) {
	t.Run("falls_back_to_default", func(t *testing.T) {
		p := &AnalysisPolicy{DefaultMaxRounds: 10}
		if got := p.MaxRoundsFor(SeverityCritical); got != 10 {
			t.Errorf("got %d, want 10", got)
		}
	})

	t.Run("override_zero_means_static_only", func(t *testing.T) {
		p := &AnalysisPolicy{
			DefaultMaxRounds: 10,
			RoundsOverrides:  map[Severity]int{SeverityInfo: 0},
		}
		if got := p.MaxRoundsFor(SeverityInfo); got != 0 {
			t.Errorf("info override 0: got %d, want 0", got)
		}
		if got := p.MaxRoundsFor(SeverityCritical); got != 10 {
			t.Errorf("critical (no override): got %d, want default 10", got)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/shared/ -run TestAnalysisPolicy -v`
Expected: FAIL — `AnalysisPolicy` undefined.

- [ ] **Step 3: Implement AnalysisPolicy**

```go
// internal/shared/policy.go
package shared

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// AnalysisPolicy is a thin decision layer that maps alert severity to model
// and tool-loop budget. It holds no mutable fields of its own; Phase 2 will
// add a Storm pointer for IsDegraded().
type AnalysisPolicy struct {
	DefaultModel     string
	ModelOverrides   map[Severity]string
	DefaultMaxRounds int
	RoundsOverrides  map[Severity]int
	GroupCooldownTTL time.Duration // Phase 2; unused in Phase 1, parsed for forward compat
}

// ModelFor returns the configured model for a given severity, falling back
// to DefaultModel when no override is set.
func (p *AnalysisPolicy) ModelFor(sev Severity) string {
	if model, ok := p.ModelOverrides[sev]; ok && model != "" {
		return model
	}
	return p.DefaultModel
}

// MaxRoundsFor returns the configured tool-loop round budget for a given
// severity, falling back to DefaultMaxRounds. A return value of 0 means
// "static-only analysis" (caller uses Analyze, not RunToolLoop).
func (p *AnalysisPolicy) MaxRoundsFor(sev Severity) int {
	if rounds, ok := p.RoundsOverrides[sev]; ok {
		return rounds
	}
	return p.DefaultMaxRounds
}

// LoadPolicy builds an AnalysisPolicy from a BaseConfig and the optional
// severity-specific environment variables defined in the spec. Returns
// an error if any override fails validation.
func LoadPolicy(base BaseConfig) (*AnalysisPolicy, error) {
	defaultRounds, err := ParseIntEnv("MAX_AGENT_ROUNDS", "10", 1, 50)
	if err != nil {
		return nil, err
	}

	modelOverrides := map[Severity]string{}
	for sev, key := range map[Severity]string{
		SeverityCritical: "CLAUDE_MODEL_CRITICAL",
		SeverityWarning:  "CLAUDE_MODEL_WARNING",
		SeverityInfo:     "CLAUDE_MODEL_INFO",
	} {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			modelOverrides[sev] = v
		}
	}

	roundsOverrides := map[Severity]int{}
	for sev, key := range map[Severity]string{
		SeverityCritical: "MAX_AGENT_ROUNDS_CRITICAL",
		SeverityWarning:  "MAX_AGENT_ROUNDS_WARNING",
		SeverityInfo:     "MAX_AGENT_ROUNDS_INFO",
	} {
		if os.Getenv(key) == "" {
			continue
		}
		v, err := ParseIntEnv(key, "", 0, 50)
		if err != nil {
			return nil, fmt.Errorf("policy: %w", err)
		}
		roundsOverrides[sev] = v
	}

	return &AnalysisPolicy{
		DefaultModel:     base.ClaudeModel,
		ModelOverrides:   modelOverrides,
		DefaultMaxRounds: defaultRounds,
		RoundsOverrides:  roundsOverrides,
	}, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/shared/ -run TestAnalysisPolicy -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/shared/policy.go internal/shared/policy_test.go
git commit -m "feat(shared): add AnalysisPolicy with severity-based model/rounds routing"
```

---

## Task 3: AlertPayload.Severity field

**Files:**
- Modify: `internal/shared/types.go:38-45`

- [ ] **Step 1: Write the failing test**

Append to `internal/shared/types_test.go`:

```go
func TestAlertPayload_HasSeverityField(t *testing.T) {
	p := AlertPayload{SeverityLevel: SeverityCritical}
	if p.SeverityLevel != SeverityCritical {
		t.Errorf("expected SeverityCritical, got %v", p.SeverityLevel)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/shared/ -run TestAlertPayload_HasSeverityField -v`
Expected: FAIL — `SeverityLevel` undefined.

- [ ] **Step 3: Add SeverityLevel field**

The existing `Severity string` field is consumed by ntfy formatting and must not be renamed. Add a new typed field next to it.

In `internal/shared/types.go`, change the `AlertPayload` struct to:

```go
// AlertPayload is the common alert representation.
type AlertPayload struct {
	Fingerprint   string
	Title         string
	Severity      string            // free-form, used for ntfy display (preserved)
	SeverityLevel Severity          // normalized, used for AnalysisPolicy routing
	Source        string            // "k8s" or "checkmk"
	Fields        map[string]string // source-specific key-value pairs
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/shared/... -v`
Expected: PASS, no regressions in other shared tests.

- [ ] **Step 5: Commit**

```bash
git add internal/shared/types.go internal/shared/types_test.go
git commit -m "feat(shared): add typed SeverityLevel field to AlertPayload"
```

---

## Task 4: k8s handler populates Severity

**Files:**
- Modify: `internal/k8s/handler.go` (around line 95 where `ap` is constructed)
- Modify: `internal/k8s/handler_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/k8s/handler_test.go`:

```go
func TestHandler_PopulatesSeverityLevel(t *testing.T) {
	cfg := Config{WebhookSecret: "x"}
	cooldown := shared.NewCooldownManager()
	metrics := &shared.AlertMetrics{}

	var captured shared.AlertPayload
	enqueue := func(p shared.AlertPayload) bool {
		captured = p
		return true
	}

	h := HandleWebhook(cfg, cooldown, enqueue, metrics)

	body := []byte(`{"alerts":[{"status":"firing","fingerprint":"fp1","labels":{"alertname":"X","severity":"critical"}}]}`)
	req := httptest.NewRequest("POST", "/webhook", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer x")
	rec := httptest.NewRecorder()
	h(rec, req)

	if captured.SeverityLevel != shared.SeverityCritical {
		t.Errorf("got %v, want SeverityCritical", captured.SeverityLevel)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/k8s/ -run TestHandler_PopulatesSeverityLevel -v`
Expected: FAIL — `SeverityLevel` is zero-value `SeverityUnknown`.

- [ ] **Step 3: Populate SeverityLevel in handler.go**

Locate the `ap := shared.AlertPayload{...}` block in `internal/k8s/handler.go` (around line 95) and add the `SeverityLevel` assignment immediately after the existing `Severity` line:

```go
ap := shared.AlertPayload{
    Fingerprint:   alert.Fingerprint,
    Title:         alert.Labels["alertname"],
    Severity:      alert.Labels["severity"],
    SeverityLevel: shared.SeverityFromAlertmanager(alert.Labels),
    Source:        "k8s",
    Fields:        make(map[string]string),
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/k8s/... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/k8s/handler.go internal/k8s/handler_test.go
git commit -m "feat(k8s): populate AlertPayload.SeverityLevel from labels"
```

---

## Task 5: checkmk handler populates Severity

**Files:**
- Modify: `internal/checkmk/handler.go` (around line 116 where `payload` is constructed)
- Modify: `internal/checkmk/handler_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/checkmk/handler_test.go`:

```go
func TestHandler_PopulatesSeverityLevel_ServiceCritical(t *testing.T) {
	cfg := Config{WebhookSecret: "x"}
	cooldown := shared.NewCooldownManager()
	metrics := &shared.AlertMetrics{}
	checkmkClient := newFakeCheckMKClient(nil)
	sshRunner := newFakeSSHRunner(nil)

	var captured shared.AlertPayload
	enqueue := func(p shared.AlertPayload) bool {
		captured = p
		return true
	}

	h := HandleWebhook(cfg, cooldown, enqueue, metrics, checkmkClient, sshRunner)

	body := []byte(`{"hostname":"h1","service_description":"svc","service_state":"CRITICAL","host_state":"","notification_type":"PROBLEM"}`)
	req := httptest.NewRequest("POST", "/webhook", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer x")
	rec := httptest.NewRecorder()
	h(rec, req)

	if captured.SeverityLevel != shared.SeverityCritical {
		t.Errorf("service CRITICAL: got %v, want SeverityCritical", captured.SeverityLevel)
	}
}

func TestHandler_PopulatesSeverityLevel_HostDown(t *testing.T) {
	cfg := Config{WebhookSecret: "x"}
	cooldown := shared.NewCooldownManager()
	metrics := &shared.AlertMetrics{}
	checkmkClient := newFakeCheckMKClient(nil)
	sshRunner := newFakeSSHRunner(nil)

	var captured shared.AlertPayload
	enqueue := func(p shared.AlertPayload) bool {
		captured = p
		return true
	}

	h := HandleWebhook(cfg, cooldown, enqueue, metrics, checkmkClient, sshRunner)

	body := []byte(`{"hostname":"h1","service_description":"","service_state":"","host_state":"DOWN","notification_type":"PROBLEM"}`)
	req := httptest.NewRequest("POST", "/webhook", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer x")
	rec := httptest.NewRecorder()
	h(rec, req)

	if captured.SeverityLevel != shared.SeverityCritical {
		t.Errorf("host DOWN: got %v, want SeverityCritical", captured.SeverityLevel)
	}
}
```

(If your existing `handler_test.go` already provides `newFakeCheckMKClient` / `newFakeSSHRunner`, reuse them; otherwise grep the file first to confirm signatures.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/checkmk/ -run TestHandler_PopulatesSeverityLevel -v`
Expected: FAIL.

- [ ] **Step 3: Populate SeverityLevel in checkmk handler**

In `internal/checkmk/handler.go`, locate the `payload := shared.AlertPayload{...}` block (around line 110) and add `SeverityLevel`:

```go
payload := shared.AlertPayload{
    Fingerprint:   fp,
    Title:         /* existing */,
    Severity:      severity, // existing free-form string
    SeverityLevel: shared.SeverityFromCheckMK(notif.ServiceState, notif.HostState),
    Source:        "checkmk",
    Fields:        /* existing */,
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/checkmk/... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/checkmk/handler.go internal/checkmk/handler_test.go
git commit -m "feat(checkmk): populate AlertPayload.SeverityLevel from state fields"
```

---

## Task 6: Cache types in shared/types.go

**Files:**
- Modify: `internal/shared/types.go:106-128` (`ToolRequest` and `ToolResponse.Usage`)

- [ ] **Step 1: Write the failing test**

Append to `internal/shared/types_test.go`:

```go
func TestSystemBlock_JSON(t *testing.T) {
	b := SystemBlock{
		Type:         "text",
		Text:         "hello",
		CacheControl: &CacheControl{Type: "ephemeral"},
	}
	out, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"type":"text","text":"hello","cache_control":{"type":"ephemeral"}}`
	if string(out) != want {
		t.Errorf("got %s, want %s", out, want)
	}
}

func TestSystemBlock_JSON_OmitsCacheControlWhenNil(t *testing.T) {
	b := SystemBlock{Type: "text", Text: "hello"}
	out, _ := json.Marshal(b)
	if !strings.Contains(string(out), `"text":"hello"`) || strings.Contains(string(out), "cache_control") {
		t.Errorf("unexpected JSON: %s", out)
	}
}

func TestToolRequest_SystemIsBlocks(t *testing.T) {
	req := ToolRequest{
		Model:     "x",
		MaxTokens: 1,
		System:    []SystemBlock{{Type: "text", Text: "p"}},
	}
	out, _ := json.Marshal(req)
	if !strings.Contains(string(out), `"system":[{"type":"text","text":"p"}]`) {
		t.Errorf("system not serialized as blocks: %s", out)
	}
}

func TestToolResponse_UsageHasCacheFields(t *testing.T) {
	body := []byte(`{"usage":{"input_tokens":1,"output_tokens":2,"cache_creation_input_tokens":3,"cache_read_input_tokens":4}}`)
	var resp ToolResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Usage.CacheCreationInputTokens != 3 {
		t.Errorf("CacheCreation: got %d", resp.Usage.CacheCreationInputTokens)
	}
	if resp.Usage.CacheReadInputTokens != 4 {
		t.Errorf("CacheRead: got %d", resp.Usage.CacheReadInputTokens)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/shared/ -run "TestSystemBlock|TestToolRequest|TestToolResponse_UsageHasCacheFields" -v`
Expected: FAIL — `SystemBlock`, `CacheControl`, and the cache fields don't exist yet.

- [ ] **Step 3: Modify types.go**

Replace the `ToolRequest` block (around line 106) and the `ToolResponse.Usage` anonymous struct (around line 120) with:

```go
// CacheControl marks a content block for prompt caching.
type CacheControl struct {
	Type string `json:"type"` // currently only "ephemeral"
}

// SystemBlock is one element of a structured system prompt; lets us attach
// cache_control to the tail of the static prompt for prompt caching.
type SystemBlock struct {
	Type         string        `json:"type"`           // "text"
	Text         string        `json:"text"`
	CacheControl *CacheControl `json:"cache_control,omitempty"`
}

// ToolRequest is the Claude Messages API request with tool support.
// System is now []SystemBlock so the last block can carry cache_control.
type ToolRequest struct {
	Model      string        `json:"model"`
	MaxTokens  int           `json:"max_tokens"`
	System     []SystemBlock `json:"system"`
	Tools      []Tool        `json:"tools,omitempty"`
	ToolChoice *ToolChoice   `json:"tool_choice,omitempty"`
	Messages   []ToolMessage `json:"messages"`
}

// ToolResponse is the Claude Messages API response with tool-use support
// and prompt-caching usage fields.
type ToolResponse struct {
	Content    []ContentBlock `json:"content"`
	StopReason string         `json:"stop_reason"`
	Usage      struct {
		InputTokens              int `json:"input_tokens"`
		OutputTokens             int `json:"output_tokens"`
		CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
		CacheReadInputTokens     int `json:"cache_read_input_tokens"`
	} `json:"usage"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}
```

Add `CacheControl *CacheControl` to `Tool` so we can mark the last tool too:

```go
type Tool struct {
	Name         string        `json:"name"`
	Description  string        `json:"description"`
	InputSchema  InputSchema   `json:"input_schema"`
	CacheControl *CacheControl `json:"cache_control,omitempty"`
}
```

Add `CacheControl *CacheControl` to `ContentBlock` so we can mark the last `tool_result` in the conversation history:

```go
type ContentBlock struct {
	Type         string          `json:"type"`
	Text         string          `json:"text,omitempty"`
	ID           string          `json:"id,omitempty"`
	Name         string          `json:"name,omitempty"`
	Input        json.RawMessage `json:"input,omitempty"`
	ToolUseID    string          `json:"tool_use_id,omitempty"`
	Content      string          `json:"content,omitempty"`
	IsError      bool            `json:"is_error,omitempty"`
	CacheControl *CacheControl   `json:"cache_control,omitempty"`
}
```

- [ ] **Step 4: Run shared package tests**

Run: `go test ./internal/shared/... -v`
Expected: the new tests PASS, and the existing `TestAnalyze*` / `TestRunToolLoop*` will FAIL because they pass `string` for `System` — that is fixed in Task 8 when we update `claude.go`. To keep this commit green, in `claude.go` temporarily wrap the existing `systemPrompt string` arg as `[]SystemBlock{{Type: "text", Text: systemPrompt}}` at the only places where `ToolRequest.System` is assigned (search `System:`). No other code change yet.

Run: `go test ./... -v`
Expected: PASS in shared/, k8s/, checkmk/.

- [ ] **Step 5: Commit**

```bash
git add internal/shared/types.go internal/shared/types_test.go internal/shared/claude.go
git commit -m "feat(shared): introduce SystemBlock/CacheControl types and cache usage fields"
```

---

## Task 7: ClaudeClient — model parameter on Analyze/RunToolLoop

**Files:**
- Modify: `internal/shared/claude.go` (functions `Analyze` and `RunToolLoop`)
- Modify: `internal/shared/interfaces.go` (the `Analyzer` and `ToolLoopRunner` interfaces)
- Modify: `internal/shared/claude_test.go`
- Modify: callers in `internal/k8s/pipeline.go`, `internal/checkmk/pipeline.go`, `internal/checkmk/agent.go`, `internal/k8s/agent.go` (and any test files mocking these)

- [ ] **Step 1: Inspect callers**

Run: `grep -rn "\.Analyze(\|\.RunToolLoop(" internal/ cmd/`

Note every call site and every implementation/mock — they all need an additional `model string` argument inserted.

- [ ] **Step 2: Write a failing test**

Append to `internal/shared/claude_test.go`:

```go
func TestAnalyze_UsesProvidedModel(t *testing.T) {
	var capturedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Write([]byte(`{"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn"}`))
	}))
	defer srv.Close()

	c := &ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "x", Model: "default-model"}
	c.retryDelays = []time.Duration{}

	if _, err := c.Analyze(context.Background(), "override-model", "sys", "usr"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(capturedBody), `"model":"override-model"`) {
		t.Errorf("expected override-model in request, got: %s", capturedBody)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/shared/ -run TestAnalyze_UsesProvidedModel -v`
Expected: FAIL — `Analyze` does not accept a model parameter yet.

- [ ] **Step 4: Update interfaces and signatures**

In `internal/shared/interfaces.go`:

```go
type Analyzer interface {
	Analyze(ctx context.Context, model, systemPrompt, userPrompt string) (string, error)
}

type ToolLoopRunner interface {
	RunToolLoop(
		ctx context.Context,
		model, systemPrompt, userPrompt string,
		tools []Tool,
		maxRounds int,
		handleTool func(name string, input json.RawMessage) (string, error),
	) (string, int, bool, error)
}
```

In `internal/shared/claude.go`, change `Analyze` to take `model string` as the second parameter and use it in the request body (replace `c.Model` at the request-construction site). Change `RunToolLoop` similarly.

`ClaudeClient.Model` becomes a fallback **only** for the case where the caller passes an empty string:

```go
func (c *ClaudeClient) Analyze(ctx context.Context, model, systemPrompt, userPrompt string) (string, error) {
	if model == "" {
		model = c.Model
	}
	// ... existing body construction, replace c.Model with model
```

Same change in `RunToolLoop`. Update both occurrences of `c.Model` inside the loop body and the forced-summary block.

- [ ] **Step 5: Update all call sites**

For each call returned by Step 1's grep, insert the second argument. Most callers will pass `cfg.ClaudeModel` (still works) or the new policy-derived model (Task 11+). For now, just thread `c.Model` through:

- `internal/k8s/pipeline.go`: at the `RunToolLoop` call, insert `cfg.ClaudeModel,` (the field still exists in `k8s.Config`) as the new model arg.
- `internal/checkmk/pipeline.go`: same.
- `internal/k8s/agent.go`, `internal/checkmk/agent.go`: same.
- Any mock client in test files: add the `model` parameter.

- [ ] **Step 6: Run all tests**

Run: `go test ./... -v`
Expected: PASS (the new test passes, all existing tests still pass because callers thread the existing model through).

- [ ] **Step 7: Commit**

```bash
git add internal/shared/claude.go internal/shared/claude_test.go internal/shared/interfaces.go internal/k8s/ internal/checkmk/
git commit -m "refactor(shared): pass model as parameter to Analyze and RunToolLoop"
```

---

## Task 8: Drop OpenRouter URL branching (breaking change)

**Files:**
- Modify: `internal/shared/claude.go` (function `isAnthropicURL` and the auth-header branch in `sendRequest`)
- Modify: `internal/shared/claude_test.go` (any test asserting Bearer behavior)

- [ ] **Step 1: Locate the branch**

Run: `grep -n "isAnthropicURL\|Authorization\|x-api-key" internal/shared/claude.go`

You should see the auth conditional in `sendRequest`.

- [ ] **Step 2: Write a test that asserts unconditional x-api-key**

Replace any existing test that exercised the Bearer path with:

```go
func TestSendRequest_AlwaysUsesXAPIKey(t *testing.T) {
	for _, url := range []string{
		"https://api.anthropic.com/v1/messages",
		"https://openrouter.ai/api/v1/messages",
		"https://example.com/proxy",
	} {
		t.Run(url, func(t *testing.T) {
			var gotKey, gotAuth, gotVersion string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotKey = r.Header.Get("x-api-key")
				gotAuth = r.Header.Get("Authorization")
				gotVersion = r.Header.Get("anthropic-version")
				w.Write([]byte(`{"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn"}`))
			}))
			defer srv.Close()

			// We override BaseURL with the *test server* URL but keep the rule:
			// the real BaseURL field doesn't determine auth anymore.
			c := &ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "tok", Model: "m"}
			c.retryDelays = []time.Duration{}
			_, err := c.Analyze(context.Background(), "m", "s", "u")
			if err != nil {
				t.Fatal(err)
			}
			if gotKey != "tok" {
				t.Errorf("x-api-key: got %q, want tok", gotKey)
			}
			if gotAuth != "" {
				t.Errorf("Authorization should be empty, got %q", gotAuth)
			}
			if gotVersion != "2023-06-01" {
				t.Errorf("anthropic-version: got %q", gotVersion)
			}
		})
	}
}
```

Delete or rewrite any existing test named like `TestSendRequest_OpenRouter*` / `TestSendRequest_BearerAuth*`.

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/shared/ -run TestSendRequest_AlwaysUsesXAPIKey -v`
Expected: FAIL — Bearer is still set for non-Anthropic URLs.

- [ ] **Step 4: Remove the branch**

In `sendRequest`, replace the auth conditional with the unconditional Anthropic header pair:

```go
req.Header.Set("Content-Type", "application/json")
req.Header.Set("x-api-key", c.APIKey)
req.Header.Set("anthropic-version", anthropicVersion)
```

Delete the `isAnthropicURL` function (and its `net/url` / `strings` imports if they become unused).

- [ ] **Step 5: Run tests**

Run: `go test ./internal/shared/... -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/shared/claude.go internal/shared/claude_test.go
git commit -m "refactor(shared)!: remove OpenRouter URL branching, always use x-api-key

BREAKING CHANGE: API_BASE_URL must accept x-api-key auth. OpenRouter standard
endpoints with Authorization: Bearer no longer work without an auth-translating
proxy. See spec docs/superpowers/specs/2026-05-01-storm-cost-protection-design.md"
```

---

## Task 9: Cache breakpoint on system prompt

**Files:**
- Modify: `internal/shared/claude.go` (functions `Analyze` and `RunToolLoop`, request body construction)
- Modify: `internal/shared/claude_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/shared/claude_test.go`:

```go
func TestAnalyze_SystemPromptHasCacheControl(t *testing.T) {
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		w.Write([]byte(`{"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn"}`))
	}))
	defer srv.Close()

	c := &ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "x", Model: "m"}
	c.retryDelays = []time.Duration{}
	if _, err := c.Analyze(context.Background(), "m", "system", "user"); err != nil {
		t.Fatal(err)
	}

	system, ok := captured["system"].([]any)
	if !ok || len(system) == 0 {
		t.Fatalf("system field is not an array: %v", captured["system"])
	}
	last := system[len(system)-1].(map[string]any)
	cc, ok := last["cache_control"].(map[string]any)
	if !ok {
		t.Fatalf("last system block has no cache_control: %v", last)
	}
	if cc["type"] != "ephemeral" {
		t.Errorf("cache_control type: got %v, want ephemeral", cc["type"])
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/shared/ -run TestAnalyze_SystemPromptHasCacheControl -v`
Expected: FAIL.

- [ ] **Step 3: Mark the system block in both Analyze and RunToolLoop**

Introduce a helper at the top of `claude.go`:

```go
// systemBlocks builds the system field with a single text block carrying
// a cache_control breakpoint at its tail. This is breakpoint #1 of the
// 4-breakpoint Anthropic budget; #2 is on the tools array, #3 on the
// last tool_result of the running conversation.
func systemBlocks(prompt string) []SystemBlock {
	return []SystemBlock{{
		Type:         "text",
		Text:         prompt,
		CacheControl: &CacheControl{Type: "ephemeral"},
	}}
}
```

In `Analyze`, replace the wrapped `[]SystemBlock{{Type: "text", Text: systemPrompt}}` (introduced in Task 6) with `systemBlocks(systemPrompt)`. In `RunToolLoop`, do the same on each `ToolRequest{...}` literal where `System:` is set (there are two: the loop body and the forced-summary call).

- [ ] **Step 4: Run tests**

Run: `go test ./internal/shared/... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/shared/claude.go internal/shared/claude_test.go
git commit -m "feat(shared): cache_control breakpoint on system prompt"
```

---

## Task 10: Cache breakpoint on tools

**Files:**
- Modify: `internal/shared/claude.go` (`RunToolLoop` only — `Analyze` doesn't send tools)
- Modify: `internal/shared/claude_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/shared/claude_test.go`:

```go
func TestRunToolLoop_LastToolHasCacheControl(t *testing.T) {
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		w.Write([]byte(`{"content":[{"type":"text","text":"done"}],"stop_reason":"end_turn"}`))
	}))
	defer srv.Close()

	c := &ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "x", Model: "m"}
	c.retryDelays = []time.Duration{}

	tools := []Tool{
		{Name: "a", Description: "first", InputSchema: InputSchema{Type: "object"}},
		{Name: "b", Description: "second", InputSchema: InputSchema{Type: "object"}},
	}
	_, _, _, err := c.RunToolLoop(context.Background(), "m", "sys", "user", tools, 1, func(string, json.RawMessage) (string, error) { return "", nil })
	if err != nil {
		t.Fatal(err)
	}

	toolsArr := captured["tools"].([]any)
	first := toolsArr[0].(map[string]any)
	last := toolsArr[len(toolsArr)-1].(map[string]any)
	if _, has := first["cache_control"]; has {
		t.Error("first tool must not carry cache_control")
	}
	cc, ok := last["cache_control"].(map[string]any)
	if !ok || cc["type"] != "ephemeral" {
		t.Errorf("last tool cache_control: got %v", last["cache_control"])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/shared/ -run TestRunToolLoop_LastToolHasCacheControl -v`
Expected: FAIL.

- [ ] **Step 3: Add `withCachedTail` helper and use it**

In `claude.go`, near `systemBlocks`:

```go
// withCachedTail returns a copy of tools with cache_control attached to the
// last element. Tools is a small slice (currently 1-2 elements), so the copy
// cost is negligible compared to building a flag at every callsite.
func withCachedTail(tools []Tool) []Tool {
	if len(tools) == 0 {
		return tools
	}
	out := make([]Tool, len(tools))
	copy(out, tools)
	out[len(out)-1].CacheControl = &CacheControl{Type: "ephemeral"}
	return out
}
```

In `RunToolLoop`, both at the loop body and in the forced-summary block, replace `Tools: tools,` with `Tools: withCachedTail(tools),`.

- [ ] **Step 4: Run tests**

Run: `go test ./internal/shared/... -v`
Expected: PASS, no regressions in existing tool-loop tests.

- [ ] **Step 5: Commit**

```bash
git add internal/shared/claude.go internal/shared/claude_test.go
git commit -m "feat(shared): cache_control breakpoint on last tool definition"
```

---

## Task 11: Cache breakpoint on tool-loop history

**Files:**
- Modify: `internal/shared/claude.go` (`RunToolLoop` — message construction inside the loop)
- Modify: `internal/shared/claude_test.go`

This is the highest-leverage cache breakpoint because the conversation history grows with each round of tool output.

- [ ] **Step 1: Write the failing test**

Append to `internal/shared/claude_test.go`:

```go
func TestRunToolLoop_LastToolResultHasCacheControl(t *testing.T) {
	round := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		round++
		body, _ := io.ReadAll(r.Body)
		// On round 2, the inbound request must contain a user message whose
		// LAST content block (= the previous tool_result) has cache_control.
		if round == 2 {
			var req map[string]any
			_ = json.Unmarshal(body, &req)
			messages := req["messages"].([]any)
			lastUserMsg := messages[len(messages)-1].(map[string]any)
			content := lastUserMsg["content"].([]any)
			lastBlock := content[len(content)-1].(map[string]any)
			if _, has := lastBlock["cache_control"]; !has {
				t.Errorf("round 2: last tool_result block missing cache_control: %v", lastBlock)
			}
		}
		// Round 1: respond with a tool_use; round 2: end_turn.
		if round == 1 {
			w.Write([]byte(`{"content":[{"type":"tool_use","id":"t1","name":"a","input":{}}],"stop_reason":"tool_use"}`))
		} else {
			w.Write([]byte(`{"content":[{"type":"text","text":"done"}],"stop_reason":"end_turn"}`))
		}
	}))
	defer srv.Close()

	c := &ClaudeClient{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "x", Model: "m"}
	c.retryDelays = []time.Duration{}

	tools := []Tool{{Name: "a", Description: "x", InputSchema: InputSchema{Type: "object"}}}
	_, rounds, _, err := c.RunToolLoop(context.Background(), "m", "sys", "user", tools, 5,
		func(string, json.RawMessage) (string, error) { return "tool-output-data", nil })
	if err != nil {
		t.Fatal(err)
	}
	if rounds != 2 {
		t.Fatalf("expected 2 rounds, got %d", rounds)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/shared/ -run TestRunToolLoop_LastToolResultHasCacheControl -v`
Expected: FAIL — last `tool_result` has no `cache_control`.

- [ ] **Step 3: Mark the last tool_result of each round**

In `RunToolLoop`, after the tool-handling loop has produced `toolResults`, but **before** appending it to `messages`, attach `CacheControl` to the last block:

```go
// Around line 308 in claude.go (before "messages = append(messages, ...)"):
if len(toolResults) > 0 {
	toolResults[len(toolResults)-1].CacheControl = &CacheControl{Type: "ephemeral"}
}
messages = append(messages, ToolMessage{Role: "user", Content: toolResults})
```

This works correctly even when the previous round's marker is still present in the message history — Anthropic's 4-breakpoint window automatically aged-out old markers, and overwriting the latest tail each round keeps the sliding cache exactly where it pays off.

In the **forced summary** block where the summary text is appended to the last user message's `[]ContentBlock`, **do not** add another cache_control marker — the latest `tool_result` already has one from its iteration, and the appended text block does not need to be cached.

- [ ] **Step 4: Run tests**

Run: `go test ./internal/shared/... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/shared/claude.go internal/shared/claude_test.go
git commit -m "feat(shared): cache_control on last tool_result block per round"
```

---

## Task 12: Token-cost Prometheus metrics

**Files:**
- Modify: `internal/shared/prom_metrics.go`
- Modify: `internal/shared/metrics.go` (helper)
- Modify: `internal/shared/claude.go` (call helper after Usage extraction)
- Modify: `internal/shared/metrics_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/shared/metrics_test.go`:

```go
func TestRecordClaudeUsage_IncrementsAllCounters(t *testing.T) {
	prom := NewPrometheusMetrics()
	m := &AlertMetrics{Prom: prom}

	usage := struct {
		InputTokens, OutputTokens, CacheCreationInputTokens, CacheReadInputTokens int
	}{InputTokens: 100, OutputTokens: 50, CacheCreationInputTokens: 200, CacheReadInputTokens: 300}

	m.RecordClaudeUsage("k8s", "warning", "claude-haiku-4-5",
		usage.InputTokens, usage.OutputTokens, usage.CacheCreationInputTokens, usage.CacheReadInputTokens)

	gather := func(name string) float64 {
		mfs, _ := prom.Registry.Gather()
		for _, mf := range mfs {
			if mf.GetName() == name {
				for _, m := range mf.GetMetric() {
					return m.GetCounter().GetValue()
				}
			}
		}
		return -1
	}
	if v := gather("claude_input_tokens_total"); v != 100 {
		t.Errorf("input_tokens: got %v, want 100", v)
	}
	if v := gather("claude_output_tokens_total"); v != 50 {
		t.Errorf("output_tokens: got %v", v)
	}
	if v := gather("claude_cache_creation_tokens_total"); v != 200 {
		t.Errorf("cache_creation: got %v", v)
	}
	if v := gather("claude_cache_read_tokens_total"); v != 300 {
		t.Errorf("cache_read: got %v", v)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/shared/ -run TestRecordClaudeUsage_IncrementsAllCounters -v`
Expected: FAIL.

- [ ] **Step 3: Add the four new CounterVecs**

In `internal/shared/prom_metrics.go`, add to the `PrometheusMetrics` struct and to `NewPrometheusMetrics()`:

```go
// Inside type PrometheusMetrics struct { ... }
ClaudeInputTokens         *prometheus.CounterVec
ClaudeOutputTokens        *prometheus.CounterVec
ClaudeCacheCreationTokens *prometheus.CounterVec
ClaudeCacheReadTokens     *prometheus.CounterVec

// Inside NewPrometheusMetrics(), before the registry.MustRegister(...) call:
labels := []string{"source", "severity", "model"}
m.ClaudeInputTokens = prometheus.NewCounterVec(
	prometheus.CounterOpts{Name: "claude_input_tokens_total", Help: "Cumulative Claude API input tokens (excluding cache hits)."},
	labels)
m.ClaudeOutputTokens = prometheus.NewCounterVec(
	prometheus.CounterOpts{Name: "claude_output_tokens_total", Help: "Cumulative Claude API output tokens."},
	labels)
m.ClaudeCacheCreationTokens = prometheus.NewCounterVec(
	prometheus.CounterOpts{Name: "claude_cache_creation_tokens_total", Help: "Cumulative tokens that produced new cache entries."},
	labels)
m.ClaudeCacheReadTokens = prometheus.NewCounterVec(
	prometheus.CounterOpts{Name: "claude_cache_read_tokens_total", Help: "Cumulative tokens served from cache."},
	labels)

// Add these four to the Registry.MustRegister(...) call.
```

- [ ] **Step 4: Add helper in metrics.go**

In `internal/shared/metrics.go`:

```go
// RecordClaudeUsage increments all four token counters with consistent labels.
// It is safe to call when m.Prom is nil (no-op).
func (m *AlertMetrics) RecordClaudeUsage(source, severity, model string, in, out, cacheCreation, cacheRead int) {
	if m == nil || m.Prom == nil {
		return
	}
	labels := prometheus.Labels{"source": source, "severity": severity, "model": model}
	m.Prom.ClaudeInputTokens.With(labels).Add(float64(in))
	m.Prom.ClaudeOutputTokens.With(labels).Add(float64(out))
	m.Prom.ClaudeCacheCreationTokens.With(labels).Add(float64(cacheCreation))
	m.Prom.ClaudeCacheReadTokens.With(labels).Add(float64(cacheRead))
}
```

(Add the `prometheus` import if not present.)

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/shared/ -run TestRecordClaudeUsage_IncrementsAllCounters -v`
Expected: PASS.

- [ ] **Step 6: Wire into ClaudeClient**

The current `ClaudeClient` doesn't know `source` and `severity`. Wiring requires either a field on the client or passing them through. Cleanest: extend `WithPrometheusMetrics` to accept the source label (already passed today) and add a per-call **labelled invocation** by exposing the metrics helper through a closure. Pragmatic choice for Phase 1: pass the source via the existing `c.durationHistogram`'s label (already source-keyed) and **store source as a field**:

In `ClaudeClient`:
```go
type ClaudeClient struct {
	// existing fields ...
	metrics *AlertMetrics
	source  string
}
```

Update `WithPrometheusMetrics`:
```go
func (c *ClaudeClient) WithPrometheusMetrics(m *AlertMetrics, source string) *ClaudeClient {
	c.metrics = m
	c.source = source
	if m != nil && m.Prom != nil {
		c.durationHistogram = m.Prom.ClaudeAPIDuration.WithLabelValues(source)
	}
	return c
}
```

For per-call severity, change `Analyze` and `RunToolLoop` to accept severity as a parameter — which means another signature change. To avoid that ripple, we accept the **simpler-but-coarser** Phase-1 trade-off: the metrics use `severity="all"` for now, and Phase 2 (or a follow-up to Phase 1) can thread severity through if the operator needs it. Document this in the helper:

In `Analyze`, after the existing `slog.Info("Claude analysis complete", ...)`:

```go
c.metrics.RecordClaudeUsage(c.source, "all", model,
	result.Usage.InputTokens, result.Usage.OutputTokens,
	result.Usage.CacheCreationInputTokens, result.Usage.CacheReadInputTokens)
```

Same call in `RunToolLoop` (in the success-return paths and the forced-summary tail, accumulated against `totalInput`/`totalOutput` — but for cache fields, sum per-round into local accumulators `totalCacheCreation`, `totalCacheRead` and emit once at return).

- [ ] **Step 7: Run all tests**

Run: `go test ./... -v`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/shared/prom_metrics.go internal/shared/metrics.go internal/shared/metrics_test.go internal/shared/claude.go
git commit -m "feat(shared): add Prometheus counters for Claude token usage"
```

---

## Task 13: Wire AnalysisPolicy into k8s pipeline

**Files:**
- Modify: `internal/k8s/types.go` (`PipelineDeps`)
- Modify: `internal/k8s/pipeline.go`
- Modify: `internal/k8s/pipeline_test.go`

- [ ] **Step 1: Write the failing test**

In `internal/k8s/pipeline_test.go`, add a test that confirms the pipeline reads model + rounds from the policy and respects `rounds == 0`:

```go
func TestProcessAlert_UsesPolicyForModelAndRounds(t *testing.T) {
	mock := &mockToolRunner{wantText: "ok"}
	policy := &shared.AnalysisPolicy{
		DefaultModel:     "default-m",
		ModelOverrides:   map[shared.Severity]string{shared.SeverityCritical: "opus"},
		DefaultMaxRounds: 5,
		RoundsOverrides:  map[shared.Severity]int{shared.SeverityWarning: 0},
	}

	deps := PipelineDeps{
		ToolRunner:    mock,
		Cooldown:      shared.NewCooldownManager(),
		Metrics:       &shared.AlertMetrics{},
		Policy:        policy,
		GatherContext: func(context.Context, shared.AlertPayload) shared.AnalysisContext { return shared.AnalysisContext{} },
		Publishers:    nil,
	}

	t.Run("critical_uses_opus_with_default_rounds", func(t *testing.T) {
		mock.Reset()
		ProcessAlert(context.Background(), deps, shared.AlertPayload{
			Fingerprint: "fp", SeverityLevel: shared.SeverityCritical, Source: "k8s",
		})
		if mock.gotModel != "opus" {
			t.Errorf("model: got %q, want opus", mock.gotModel)
		}
		if mock.gotRounds != 5 {
			t.Errorf("rounds: got %d, want 5", mock.gotRounds)
		}
		if mock.calls.runToolLoop != 1 || mock.calls.analyze != 0 {
			t.Errorf("expected 1 RunToolLoop call, got %+v", mock.calls)
		}
	})

	t.Run("warning_with_zero_rounds_uses_Analyze", func(t *testing.T) {
		mock.Reset()
		ProcessAlert(context.Background(), deps, shared.AlertPayload{
			Fingerprint: "fp", SeverityLevel: shared.SeverityWarning, Source: "k8s",
		})
		if mock.gotModel != "default-m" {
			t.Errorf("model: got %q, want default-m", mock.gotModel)
		}
		if mock.calls.analyze != 1 || mock.calls.runToolLoop != 0 {
			t.Errorf("expected 1 Analyze call, got %+v", mock.calls)
		}
	})
}
```

`mockToolRunner` needs to satisfy both `Analyzer` and `ToolLoopRunner` and remember model/rounds — extend the existing mock in this file (grep for `mockToolRunner` first; if it exists, add fields and a `Reset()`; otherwise create one):

```go
type mockToolRunner struct {
	wantText  string
	gotModel  string
	gotRounds int
	calls     struct{ analyze, runToolLoop int }
}

func (m *mockToolRunner) Reset() { *m = mockToolRunner{wantText: m.wantText} }

func (m *mockToolRunner) Analyze(_ context.Context, model, _, _ string) (string, error) {
	m.gotModel = model
	m.gotRounds = 0
	m.calls.analyze++
	return m.wantText, nil
}

func (m *mockToolRunner) RunToolLoop(_ context.Context, model, _, _ string, _ []shared.Tool, rounds int, _ func(string, json.RawMessage) (string, error)) (string, int, bool, error) {
	m.gotModel = model
	m.gotRounds = rounds
	m.calls.runToolLoop++
	return m.wantText, rounds, false, nil
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/k8s/ -run TestProcessAlert_UsesPolicyForModelAndRounds -v`
Expected: FAIL — `Policy` field doesn't exist on `PipelineDeps`.

- [ ] **Step 3: Add Policy to PipelineDeps and use it in ProcessAlert**

In `internal/k8s/types.go`, change `PipelineDeps`:
- Remove field `MaxAgentRounds int` (now lives on Policy)
- Add field `Policy *shared.AnalysisPolicy`
- Keep `ToolRunner` as the union type `interface { shared.Analyzer; shared.ToolLoopRunner }` (introduce this typed alias if not present)

In `internal/k8s/pipeline.go`, find the place where `RunToolLoop` is called. Replace the model and rounds source:

```go
model := deps.Policy.ModelFor(alert.SeverityLevel)
rounds := deps.Policy.MaxRoundsFor(alert.SeverityLevel)

var (
	analysis string
	err      error
)
if rounds == 0 {
	analysis, err = deps.ToolRunner.Analyze(ctx, model, systemPrompt, userPrompt)
} else {
	analysis, _, _, err = deps.ToolRunner.RunToolLoop(ctx, model, systemPrompt, userPrompt, tools, rounds, handleTool)
}
```

(Adapt variable names to whatever the existing `pipeline.go` already uses; the key change is replacing `cfg.ClaudeModel` with `model`, replacing `deps.MaxAgentRounds` with `rounds`, and switching on `rounds == 0`.)

- [ ] **Step 4: Run tests**

Run: `go test ./internal/k8s/... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/k8s/types.go internal/k8s/pipeline.go internal/k8s/pipeline_test.go
git commit -m "feat(k8s): pipeline routes model and rounds via AnalysisPolicy"
```

---

## Task 14: Wire AnalysisPolicy into checkmk pipeline

**Files:**
- Modify: `internal/checkmk/types.go`
- Modify: `internal/checkmk/pipeline.go`
- Modify: `internal/checkmk/pipeline_test.go`

Mirror Task 13 for the checkmk package: same `Policy *shared.AnalysisPolicy` field, same `ModelFor` / `MaxRoundsFor` calls, same `rounds == 0 → Analyze` switch, equivalent test cases.

- [ ] **Step 1: Write the failing test (mirror of Task 13)**

(Use the same test scaffolding pattern; replace `k8s` with `checkmk` and `Source: "k8s"` with `Source: "checkmk"`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/checkmk/ -run TestProcessAlert_UsesPolicyForModelAndRounds -v`
Expected: FAIL.

- [ ] **Step 3: Modify types.go and pipeline.go**

Same structural change as Task 13. Note that checkmk also has `internal/checkmk/agent.go` which calls `RunToolLoop` for the agentic SSH loop — update its call to take the same model:

```go
// in agent.go where RunToolLoop is called
analysis, _, _, err := runner.RunToolLoop(ctx, model, systemPrompt, userPrompt, tools, rounds, handler)
```

`model` and `rounds` flow from the pipeline through into the agent invocation.

- [ ] **Step 4: Run tests**

Run: `go test ./internal/checkmk/... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/checkmk/types.go internal/checkmk/pipeline.go internal/checkmk/agent.go internal/checkmk/pipeline_test.go
git commit -m "feat(checkmk): pipeline routes model and rounds via AnalysisPolicy"
```

---

## Task 15: Wire policy in cmd/k8s-analyzer/main.go

**Files:**
- Modify: `cmd/k8s-analyzer/main.go`

- [ ] **Step 1: Inspect current wiring**

Run: `grep -n "MaxAgentRounds\|deps :=" cmd/k8s-analyzer/main.go`

Note the lines that build `PipelineDeps` (line ~99 in the current source) and remove `MaxAgentRounds: cfg.MaxAgentRounds`.

- [ ] **Step 2: Add policy load and wiring**

After `cfg := loadConfig()` (line 74), add:

```go
policy, err := shared.LoadPolicy(cfg.BaseConfig())
if err != nil {
	slog.Error("policy config", "error", err)
	os.Exit(1)
}
```

Replace the `deps := k8s.PipelineDeps{...}` block: remove `MaxAgentRounds: cfg.MaxAgentRounds,` and add `Policy: policy,`.

In the `slog.Info("K8s Alert Analyzer started", ...)` call, replace `"maxAgentRounds", cfg.MaxAgentRounds` with `"defaultRounds", policy.DefaultMaxRounds, "modelOverrides", len(policy.ModelOverrides)`.

Optionally remove the `cfg.MaxAgentRounds` field from `k8s.Config` and the matching `loadConfig()` lines now that nothing reads it. Keep the `MAX_AGENT_ROUNDS` ENV variable parsing — it's still read by `LoadPolicy`.

Concretely, in `loadConfig()`:
- Delete the `maxAgentRounds, err := shared.ParseIntEnv("MAX_AGENT_ROUNDS", "10", 1, 50)` block
- Delete `MaxAgentRounds: maxAgentRounds,` from the `k8s.Config` literal

(`LoadPolicy` reads `MAX_AGENT_ROUNDS` itself.)

- [ ] **Step 3: Build & run**

```bash
CGO_ENABLED=0 go build -o /tmp/k8s-analyzer ./cmd/k8s-analyzer/
```

Expected: builds without errors.

- [ ] **Step 4: Commit**

```bash
git add cmd/k8s-analyzer/main.go internal/k8s/types.go
git commit -m "feat(k8s): wire AnalysisPolicy in main entrypoint"
```

---

## Task 16: Wire policy in cmd/checkmk-analyzer/main.go

**Files:**
- Modify: `cmd/checkmk-analyzer/main.go`

Mirror Task 15 in the checkmk binary: call `shared.LoadPolicy(cfg.BaseConfig())`, drop `MaxAgentRounds` from `Config`, inject `Policy` into the deps struct.

- [ ] **Step 1: Apply the same edit pattern as Task 15**

- [ ] **Step 2: Build**

```bash
CGO_ENABLED=0 go build -o /tmp/checkmk-analyzer ./cmd/checkmk-analyzer/
```

Expected: builds without errors.

- [ ] **Step 3: Commit**

```bash
git add cmd/checkmk-analyzer/main.go internal/checkmk/types.go
git commit -m "feat(checkmk): wire AnalysisPolicy in main entrypoint"
```

---

## Task 17: Update CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Add a new "Cost & Storm Protection (Phase 1)" section**

Add to `CLAUDE.md` between "Environment Variables" and "CI & Deployment":

````markdown
## Cost & Storm Protection (Phase 1)

The analyzers route Claude API calls based on alert severity to reduce cost. Defaults preserve current behavior — overrides are opt-in.

### Severity-based model routing
- `CLAUDE_MODEL_CRITICAL` (default: `$CLAUDE_MODEL`)
- `CLAUDE_MODEL_WARNING` (default: `$CLAUDE_MODEL`)
- `CLAUDE_MODEL_INFO` (default: `$CLAUDE_MODEL`)

Suggested setup: critical → Opus, warning/info → Haiku. Reduces cost ~12× for non-critical alerts.

### Severity-based agent rounds (range 0-50, optional)
- `MAX_AGENT_ROUNDS_CRITICAL` (default: `$MAX_AGENT_ROUNDS`)
- `MAX_AGENT_ROUNDS_WARNING` (default: `$MAX_AGENT_ROUNDS`)
- `MAX_AGENT_ROUNDS_INFO` (default: `$MAX_AGENT_ROUNDS`)

Special value `0` skips the tool-loop entirely and runs a static `Analyze` only — best for noisy info alerts.

### Prompt caching
Enabled automatically. Anthropic prompt caching is applied at three breakpoints:
- system prompt (last block)
- tool definitions (last tool)
- tool-loop conversation history (last `tool_result` per round)

Hit-rate is visible via Prometheus metrics:
- `claude_input_tokens_total{source,severity,model}`
- `claude_output_tokens_total{source,severity,model}`
- `claude_cache_creation_tokens_total{source,severity,model}`
- `claude_cache_read_tokens_total{source,severity,model}`

Anthropic only caches blocks larger than ~1024 tokens (Sonnet/Opus, ~2048 for Haiku). For small system prompts, expect cache benefit only on the tool-loop history.

## ⚠️ Breaking Change in Phase 1: OpenRouter Bearer auth removed

`API_BASE_URL` must accept `x-api-key` authentication. Until this version, the client auto-detected `anthropic.com` URLs and switched to `Authorization: Bearer` for everything else (typically OpenRouter). That URL-conditional code is gone — both headers are no longer set together; only `x-api-key` is sent.

If you run against OpenRouter via `Authorization: Bearer`, you must put a header-translating proxy in front, or migrate to a different Anthropic-API-compatible provider that accepts `x-api-key`.
````

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: document Phase 1 cost protection knobs and OpenRouter breaking change"
```

---

## Task 18: Phase 1 integration sanity check

**Files:** none (verification only)

- [ ] **Step 1: Full test suite**

```bash
go test ./... -race
```

Expected: all PASS, no race detector findings.

- [ ] **Step 2: Build both binaries**

```bash
CGO_ENABLED=0 go build -o /tmp/k8s-analyzer ./cmd/k8s-analyzer/
CGO_ENABLED=0 go build -o /tmp/checkmk-analyzer ./cmd/checkmk-analyzer/
```

Expected: clean builds.

- [ ] **Step 3: Smoke-run k8s-analyzer (config validation only)**

```bash
WEBHOOK_SECRET=x API_KEY=y CLAUDE_MODEL=claude-sonnet-4-6 \
  CLAUDE_MODEL_WARNING=claude-haiku-4-5 \
  MAX_AGENT_ROUNDS_INFO=0 \
  /tmp/k8s-analyzer 2>&1 | head -5
```

Expected: log line shows the analyzer started (or k8s in-cluster config error — that's fine, we only need the config to load). No panic, no `policy config` error.

- [ ] **Step 4: Verify `/metrics` exposes new counters**

(Skip in CI; manual smoke step. After running locally with mock dependencies or in staging, scrape `:9101/metrics` and confirm the four `claude_*_tokens_total` series appear with `source`/`severity`/`model` labels.)

- [ ] **Step 5: Commit (no code change — gate marker)**

If everything is green, this task adds no commit. If any test broke or builds failed, fix forward in a new commit before proceeding.

---

## Self-Review Notes

Verified inline before marking the plan complete:

1. **Spec coverage** — Each Phase 1 spec section maps to a task:
   - 1.1 Caching → Tasks 6, 9, 10, 11
   - 1.2 OpenRouter breaking change → Task 8
   - 1.3 Severity model routing → Tasks 1, 2, 4, 5, 13, 14, 15, 16
   - 1.4 Severity rounds (incl. 0) → Tasks 2, 13, 14
   - 1.5 Cost metrics → Task 12
   - Severity model itself → Tasks 1, 3
   - CLAUDE.md docs → Task 17

2. **Placeholder scan** — No "TBD" / "TODO" / "implement later". One comment ("If your existing handler_test already provides…") instructs grep verification rather than guessing — that's allowed.

3. **Type/method consistency** —
   - `Severity`, `SeverityLevel`, `AnalysisPolicy.ModelFor`, `AnalysisPolicy.MaxRoundsFor`, `LoadPolicy`, `RecordClaudeUsage`, `systemBlocks`, `withCachedTail`, `CacheControl`, `SystemBlock`, `CacheCreationInputTokens`, `CacheReadInputTokens` — all consistent across tasks.
   - `Analyze`/`RunToolLoop` signature change introduced in Task 7 and assumed by Tasks 9–14.

4. **Phase 2 deferral** — Storm-Mode, Group-Cooldown, Circuit-Breaker, Verstärker-Bug sequence test, half-open probe limitation test are intentionally **out of this plan**. A separate plan will be written after Phase 1 ships and metrics are observed.

---

## Phase 2 (out of scope here)

After Phase 1 is merged and observed in staging for 24-72 hours, write a new plan covering:
- `internal/shared/storm.go` — `StormDetector` with sliding-window mutex, `now`-injection
- `internal/shared/breaker.go` — `CircuitBreaker` with `BeforeCall`/`RecordResult`/`IsHalfOpenProbe`, half-open mutex gate
- `CooldownManager.CheckAndSetGroup`/`ClearGroup`
- Pipeline-failure phase differentiation (pre-API / API / post-API)
- Pipeline forces `rounds=0` when `policy.IsDegraded()` or `breaker.IsHalfOpenProbe()`
- ntfy aggregator for Storm and Breaker notifications
- Two sequence tests: Verstärker-Bug, Half-Open-Probe limitation

Spec reference: sections 2.1–2.4 of `docs/superpowers/specs/2026-05-01-storm-cost-protection-design.md`.
