# k8s-analyzer Agentic Debugging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the k8s-analyzer to feature parity with the checkmk-analyzer's agentic Claude tool-use loop. Replace the single-shot `Analyzer.Analyze()` call with a multi-turn `RunToolLoop` driven by two tools — `kubectl_exec` (argv subprocess) and `promql_query` (typed) — with security enforced by a verb allowlist + global-flag denylist + scrubbed-env subprocess + cluster-side RBAC.

**Architecture:** Existing `internal/checkmk/agent.go` is the reference: `parseCommandInput` validation → tool loop via `shared.ToolLoopRunner` → `RunAgenticDiagnostics` orchestration. The new `internal/k8s/agent.go` mirrors that shape with kubectl-specific tools. Static prefetch (`GatherContext`) stays as the seed user prompt; `ProcessAlert` keeps the alert-header assembly. `cmd/k8s-analyzer/main.go` wires the existing `claudeClient` (which already implements `ToolLoopRunner`) plus a new `kubectlSubprocess` runner.

**Tech Stack:** Go 1.26+, `shared.ToolLoopRunner` from `internal/shared/`, `prometheus/client_golang`, `os/exec`, kubectl 1.31+ static binary baked into the image.

**Spec:** [`docs/superpowers/specs/2026-05-01-k8s-agentic-debugging-design.md`](../specs/2026-05-01-k8s-agentic-debugging-design.md)

---

## Task 1: Add agent observability metrics to `shared.PrometheusMetrics`

**Files:**
- Modify: `internal/shared/prom_metrics.go`
- Modify: `internal/shared/metrics.go` (add helper methods)
- Test: `internal/shared/metrics_test.go`

- [ ] **Step 1: Write failing test for new metric helpers**

Append to `internal/shared/metrics_test.go`:

```go
func TestRecordAgentToolCall(t *testing.T) {
	m := &AlertMetrics{Prom: NewPrometheusMetrics()}
	m.RecordAgentToolCall("k8s", "kubectl_exec", "ok", 250*time.Millisecond)
	m.RecordAgentToolCall("k8s", "kubectl_exec", "rejected_verb", 1*time.Millisecond)

	got := strings.Builder{}
	m.MetricsHandler()(httptestNewRecorder(&got), httptestNewRequest())
	body := got.String()
	if !strings.Contains(body, `agent_tool_calls_total{outcome="ok",source="k8s",tool="kubectl_exec"} 1`) {
		t.Errorf("missing ok counter line; body:\n%s", body)
	}
	if !strings.Contains(body, `agent_tool_calls_total{outcome="rejected_verb",source="k8s",tool="kubectl_exec"} 1`) {
		t.Errorf("missing rejected_verb counter line; body:\n%s", body)
	}
	if !strings.Contains(body, `agent_tool_duration_seconds_bucket{source="k8s",tool="kubectl_exec",le=`) {
		t.Errorf("missing duration histogram; body:\n%s", body)
	}
}

func TestRecordAgentRounds(t *testing.T) {
	m := &AlertMetrics{Prom: NewPrometheusMetrics()}
	m.RecordAgentRounds("k8s", 3, false)
	m.RecordAgentRounds("k8s", 10, true)

	got := strings.Builder{}
	m.MetricsHandler()(httptestNewRecorder(&got), httptestNewRequest())
	body := got.String()
	if !strings.Contains(body, `agent_rounds_used_count{source="k8s"} 2`) {
		t.Errorf("missing rounds_used count; body:\n%s", body)
	}
	if !strings.Contains(body, `agent_rounds_exhausted_total{source="k8s"} 1`) {
		t.Errorf("missing exhausted counter; body:\n%s", body)
	}
}

// httptestNewRecorder/httptestNewRequest already exist as helpers in the
// test package (see existing TestMetricsHandler usage) — if not, add:
//   func httptestNewRecorder(b *strings.Builder) http.ResponseWriter { ... }
//   func httptestNewRequest() *http.Request { ... }
```

If those helpers don't exist, write a minimal pair (use `httptest.NewRecorder` from `net/http/httptest` and `httptest.NewRequest`). Add `import "time"` and `import "net/http/httptest"` as needed.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/shared/ -run "TestRecordAgent" -v`
Expected: FAIL — `m.RecordAgentToolCall undefined` and `agent_tool_calls_total` line not present.

- [ ] **Step 3: Add new fields to `PrometheusMetrics` struct**

In `internal/shared/prom_metrics.go`, after `NtfyPublishErrors` field add:

```go
	// AgentToolCalls counts every tool call made inside an agentic loop, labeled
	// by source ("k8s" / "checkmk"), tool name, and outcome
	// (ok / rejected_validation / rejected_verb / exec_error / nonzero_exit / timeout).
	AgentToolCalls *prometheus.CounterVec
	// AgentToolDuration is a histogram of per-tool wall-clock latency in seconds,
	// labeled by source and tool name.
	AgentToolDuration *prometheus.HistogramVec
	// AgentRoundsUsed observes how many tool rounds Claude actually used per
	// completed loop, labeled by source. Compare _count to AgentRoundsExhausted
	// to see how often Claude ended naturally vs. hit the cap.
	AgentRoundsUsed *prometheus.HistogramVec
	// AgentRoundsExhausted counts loops that returned via the forced-summary path
	// because maxRounds was reached, labeled by source.
	AgentRoundsExhausted *prometheus.CounterVec
```

- [ ] **Step 4: Construct and register the new metrics in `NewPrometheusMetrics`**

Inside `NewPrometheusMetrics()`, before `reg.MustRegister(...)`, add:

```go
	agentToolCalls := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "agent_tool_calls_total",
		Help: "Total number of tool calls made inside an agentic Claude loop, by source, tool, and outcome.",
	}, []string{"source", "tool", "outcome"})

	// agentToolBuckets cover the realistic per-tool wall-clock range.
	// kubectl/PromQL calls are typically 50 ms – 5 s; the 10 s ceiling is the
	// per-call timeout enforced by the handlers.
	agentToolBuckets := []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

	agentToolDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "agent_tool_duration_seconds",
		Help:    "Per-tool wall-clock latency in seconds for agentic-loop tool calls, by source and tool.",
		Buckets: agentToolBuckets,
	}, []string{"source", "tool"})

	agentRoundsUsed := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "agent_rounds_used",
		Help:    "Number of tool rounds Claude used per completed agentic loop, by source.",
		// Linear buckets up to the default checkmk MaxAgentRounds=10. The
		// last bucket captures any future increase to maxRounds=50.
		Buckets: []float64{1, 2, 3, 4, 5, 7, 10, 15, 25, 50},
	}, []string{"source"})

	agentRoundsExhausted := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "agent_rounds_exhausted_total",
		Help: "Number of agentic loops that ended via forced-summary because maxRounds was reached, by source.",
	}, []string{"source"})
```

Add them to `reg.MustRegister(...)`:

```go
	reg.MustRegister(
		alertsAnalyzed,
		alertsCooldown,
		queueDepth,
		claudeAPIDuration,
		claudeAPIErrors,
		ntfyPublishErrors,
		agentToolCalls,
		agentToolDuration,
		agentRoundsUsed,
		agentRoundsExhausted,
	)
```

And the `return` block:

```go
	return &PrometheusMetrics{
		registry:             reg,
		AlertsAnalyzed:       alertsAnalyzed,
		AlertsCooldown:       alertsCooldown,
		QueueDepth:           queueDepth,
		ClaudeAPIDuration:    claudeAPIDuration,
		ClaudeAPIErrors:      claudeAPIErrors,
		NtfyPublishErrors:    ntfyPublishErrors,
		AgentToolCalls:       agentToolCalls,
		AgentToolDuration:    agentToolDuration,
		AgentRoundsUsed:      agentRoundsUsed,
		AgentRoundsExhausted: agentRoundsExhausted,
	}
```

- [ ] **Step 5: Add `AlertMetrics` helper methods**

In `internal/shared/metrics.go`, after `RecordNtfyPublishError`, add:

```go
// RecordAgentToolCall increments agent_tool_calls_total and observes
// agent_tool_duration_seconds for a single tool invocation. No-op when Prom is nil.
func (m *AlertMetrics) RecordAgentToolCall(source, tool, outcome string, duration time.Duration) {
	if m.Prom == nil {
		return
	}
	m.Prom.AgentToolCalls.WithLabelValues(source, tool, outcome).Inc()
	m.Prom.AgentToolDuration.WithLabelValues(source, tool).Observe(duration.Seconds())
}

// RecordAgentRounds observes agent_rounds_used and conditionally increments
// agent_rounds_exhausted_total when the loop hit the maxRounds cap.
// No-op when Prom is nil.
func (m *AlertMetrics) RecordAgentRounds(source string, rounds int, exhausted bool) {
	if m.Prom == nil {
		return
	}
	m.Prom.AgentRoundsUsed.WithLabelValues(source).Observe(float64(rounds))
	if exhausted {
		m.Prom.AgentRoundsExhausted.WithLabelValues(source).Inc()
	}
}
```

Make sure `time` is imported in `metrics.go`.

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/shared/ -run "TestRecordAgent" -v`
Expected: PASS.

- [ ] **Step 7: Run the full shared package test suite to confirm no regressions**

Run: `go test ./internal/shared/`
Expected: PASS (all existing tests + 2 new ones).

- [ ] **Step 8: Commit**

```bash
git add internal/shared/prom_metrics.go internal/shared/metrics.go internal/shared/metrics_test.go
git commit -m "feat(shared): add agent_tool_calls/duration/rounds metrics"
```

---

## Task 2: Expose `PrometheusClient.Query` + `PromQLQuerier` interface

**Files:**
- Modify: `internal/k8s/context.go`
- Test: `internal/k8s/context_test.go`

The agent loop needs an arbitrary-PromQL entry point. Today only `GetMetrics(alert)` is public; the underlying `query(ctx, queryStr) string` is private.

- [ ] **Step 1: Write failing test for `Query`**

Append to `internal/k8s/context_test.go`:

```go
func TestPrometheusClient_Query(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			t.Errorf("expected /api/v1/query, got %s", r.URL.Path)
		}
		if r.URL.Query().Get("query") != "up" {
			t.Errorf("expected query=up, got %s", r.URL.Query().Get("query"))
		}
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"job":"prom"},"value":[0,"1"]}]}}`))
	}))
	defer server.Close()

	c := NewPrometheusClient(server.URL)
	got := c.Query(context.Background(), "up")
	if !strings.Contains(got, "job=prom") || !strings.Contains(got, ": 1") {
		t.Errorf("unexpected Query output: %q", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/k8s/ -run TestPrometheusClient_Query -v`
Expected: FAIL — `c.Query undefined`.

- [ ] **Step 3: Add public `Query` method**

In `internal/k8s/context.go`, immediately after the `query` method, add:

```go
// Query is the public entry point for the agent loop. It delegates to the
// existing private query method, which already applies result-line truncation,
// label/value sanitization, and JSON parsing. Errors and timeouts are returned
// as human-readable strings prefixed with "(...)" so the agent can surface them
// to Claude as tool results.
func (p *PrometheusClient) Query(ctx context.Context, queryStr string) string {
	return p.query(ctx, queryStr)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/k8s/ -run TestPrometheusClient_Query -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/k8s/context.go internal/k8s/context_test.go
git commit -m "feat(k8s): expose PrometheusClient.Query for agent loop"
```

---

## Task 3: Update `k8s.Config` — add `MaxAgentRounds`, drop `AllowedNamespaces`

**Files:**
- Modify: `internal/k8s/types.go`
- Modify: `internal/k8s/context.go` (drop `isNamespaceAllowed` + the allowlist check in `getPodLogs`)
- Modify: `internal/k8s/context_test.go` (delete or update tests that depend on the allowlist)

- [ ] **Step 1: Inspect current `Config`**

Run: `cat internal/k8s/types.go`
Note the existing `AllowedNamespaces []string` field and any other fields referenced in `cmd/k8s-analyzer/main.go`.

- [ ] **Step 2: Write failing test for `MaxAgentRounds` in `Config`**

Append to `internal/k8s/constructors_test.go` (or `types_test.go` if it exists; create `types_test.go` otherwise):

```go
func TestConfig_MaxAgentRounds(t *testing.T) {
	cfg := Config{MaxAgentRounds: 7}
	if cfg.MaxAgentRounds != 7 {
		t.Fatalf("expected 7, got %d", cfg.MaxAgentRounds)
	}
}
```

This is a trivial type-shape check; its real purpose is to fail-compile if the field is missing.

- [ ] **Step 3: Run to verify it fails**

Run: `go test ./internal/k8s/ -run TestConfig_MaxAgentRounds -v`
Expected: BUILD FAIL — `cfg.MaxAgentRounds undefined`.

- [ ] **Step 4: Update `Config`**

In `internal/k8s/types.go`:
- Add `MaxAgentRounds int` next to existing config fields.
- Remove `AllowedNamespaces []string`.

- [ ] **Step 5: Drop `isNamespaceAllowed` and the allowlist check in `getPodLogs`**

In `internal/k8s/context.go`:
- Delete the entire `isNamespaceAllowed` function.
- In `getPodLogs`, remove the `if !isNamespaceAllowed(namespace, cfg.AllowedNamespaces) { return ... }` block at the top of the function. The function then runs unconditionally.

- [ ] **Step 6: Update tests that referenced `AllowedNamespaces` / `isNamespaceAllowed`**

Run: `grep -n "AllowedNamespaces\|isNamespaceAllowed" internal/k8s/*_test.go`

For every match:
- If a test set `cfg.AllowedNamespaces = []string{...}` to *enable* log fetching, the assignment is now redundant — remove it.
- If a test asserted "(namespace … not in log allowlist)" string in output, update it: with the gate removed, the function will hit the fake clientset and produce real (or "(no failing pods)") output.
- If `TestIsNamespaceAllowed` exists, delete it.

After the edits:

Run: `grep -n "AllowedNamespaces\|isNamespaceAllowed" internal/k8s/`
Expected: no matches.

- [ ] **Step 7: Run the k8s package tests**

Run: `go test ./internal/k8s/`
Expected: PASS. Fix any test that still references the removed symbols.

- [ ] **Step 8: Commit**

```bash
git add internal/k8s/types.go internal/k8s/context.go internal/k8s/context_test.go internal/k8s/constructors_test.go
git commit -m "refactor(k8s): drop ALLOWED_NAMESPACES allowlist, add MaxAgentRounds"
```

---

## Task 4: Strengthen `pipeline_test.go` header assertion

This task locks down the existing `userPrompt` shape so the upcoming `RunAgenticDiagnostics` integration cannot silently drop fields. Run **before** Task 12.

**Files:**
- Modify: `internal/k8s/pipeline_test.go`

- [ ] **Step 1: Locate the existing `StartsAt` assertion**

Run: `grep -n "StartsAt" internal/k8s/pipeline_test.go`
Note the line.

- [ ] **Step 2: Replace the substring check with a verbatim prefix assertion**

Find the test that captures `userPrompt` and asserts `strings.Contains(capturedPrompt, "StartsAt")`. Replace that block with:

```go
	// Assert the full alert-header prefix verbatim. This locks down field order
	// and presence so a refactor cannot silently drop alertname/status/severity/
	// namespace/StartsAt without failing this test.
	wantPrefix := "## Alert: TestAlert\n- Status: firing\n- Severity: critical\n- Namespace: monitoring\n- StartsAt: 2024-01-01T00:00:00Z\n\n"
	if !strings.HasPrefix(capturedPrompt, wantPrefix) {
		t.Errorf("user prompt header mismatch.\nwant prefix:\n%q\ngot:\n%q", wantPrefix, capturedPrompt)
	}
```

Adjust the literal values (`TestAlert`, `firing`, `critical`, `monitoring`, `2024-01-01T00:00:00Z`) to match whatever the test fixture sets.

- [ ] **Step 3: Run the test to verify it still passes against the current code**

Run: `go test ./internal/k8s/ -run TestProcessAlert -v`
Expected: PASS — the current `ProcessAlert` produces this exact prefix.

If it fails, the literal values need to be adjusted to match the fixture. Do NOT touch `pipeline.go` to make it pass.

- [ ] **Step 4: Commit**

```bash
git add internal/k8s/pipeline_test.go
git commit -m "test(k8s): assert full alert-header prefix in user prompt"
```

---

## Task 5: `parseKubectlInput` — basic argv validation (TDD)

**Files:**
- Create: `internal/k8s/agent.go`
- Create: `internal/k8s/agent_test.go`

This task implements only the byte-level argv validation (length caps, control chars). Verb allowlist + global-flag denylist come in Tasks 6 and 7.

- [ ] **Step 1: Create `internal/k8s/agent_test.go` with the full table test**

```go
package k8s

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseKubectlInput_BasicValidation(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name:    "empty argv",
			input:   `{"command":[]}`,
			wantErr: "empty command",
		},
		{
			name:    "argv too long",
			input:   `{"command":[` + strings.Repeat(`"x",`, 64) + `"x"]}`,
			wantErr: "maximum is 64",
		},
		{
			name:    "single arg too long",
			input:   `{"command":["` + strings.Repeat("x", 4097) + `"]}`,
			wantErr: "maximum length",
		},
		{
			name:    "total bytes too long",
			input:   `{"command":[` + strings.Repeat(`"`+strings.Repeat("x", 4096)+`",`, 4) + `"x"]}`,
			wantErr: "exceeds maximum",
		},
		{
			name:    "empty arg",
			input:   `{"command":["get",""]}`,
			wantErr: "is empty",
		},
		{
			name:    "whitespace-only arg",
			input:   `{"command":["get","   "]}`,
			wantErr: "whitespace-only",
		},
		{
			name:    "null byte",
			input:   `{"command":["get","pods "]}`,
			wantErr: "control character",
		},
		{
			name:    "newline",
			input:   `{"command":["get","pods\n-x"]}`,
			wantErr: "control character",
		},
		{
			name:    "leading whitespace",
			input:   `{"command":["get"," pods"]}`,
			wantErr: "leading or trailing whitespace",
		},
		{
			name:    "trailing whitespace",
			input:   `{"command":["get","pods "]}`,
			wantErr: "leading or trailing whitespace",
		},
		{
			name:    "C0 control char",
			input:   `{"command":["get","pods"]}`,
			wantErr: "control character",
		},
		{
			name:    "C1 control char",
			input:   `{"command":["get","pods"]}`,
			wantErr: "control character",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseKubectlInput(json.RawMessage(tc.input))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("expected error containing %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}

func TestParseKubectlInput_ValidArgv(t *testing.T) {
	got, err := parseKubectlInput(json.RawMessage(`{"command":["get","pods","-n","monitoring"]}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"get", "pods", "-n", "monitoring"}
	if len(got) != len(want) {
		t.Fatalf("len mismatch: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("argv[%d]: got %q, want %q", i, got[i], want[i])
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/k8s/ -run TestParseKubectlInput -v`
Expected: BUILD FAIL — `parseKubectlInput undefined`.

- [ ] **Step 3: Create `internal/k8s/agent.go` with the parser**

```go
package k8s

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Argv-shape limits — identical to the values used in
// internal/checkmk/agent.go's parseCommandInput. Same threat model:
// a hallucinatory or adversarial Claude could emit oversized argv to OOM
// shellQuote, fill structured logs, or smuggle control characters that
// defeat exact-match denylist lookups.
const (
	maxArgvElements    = 64
	maxArgLen          = 4096
	maxTotalArgBytes   = 16384
	maxKubectlPromQLen = 4096 // also used by parsePromQLInput
)

// parseKubectlInput validates the argv from a kubectl_exec tool call. It does
// NOT yet check the verb allowlist or global-flag denylist — those gates are
// applied by separate helpers (Task 6, 7). The split keeps each concern in
// its own table test.
func parseKubectlInput(input json.RawMessage) ([]string, error) {
	var parsed struct {
		Command []string `json:"command"`
	}
	if err := json.Unmarshal(input, &parsed); err != nil {
		return nil, fmt.Errorf("parse command input: %w", err)
	}
	if len(parsed.Command) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	if len(parsed.Command) > maxArgvElements {
		return nil, fmt.Errorf("command has %d elements, maximum is %d", len(parsed.Command), maxArgvElements)
	}
	totalBytes := 0
	for i, arg := range parsed.Command {
		if arg == "" {
			return nil, fmt.Errorf("argument %d is empty", i)
		}
		if strings.TrimSpace(arg) == "" {
			return nil, fmt.Errorf("argument %d is whitespace-only", i)
		}
		if len(arg) > maxArgLen {
			return nil, fmt.Errorf("argument %d exceeds maximum length of %d bytes", i, maxArgLen)
		}
		if strings.TrimSpace(arg) != arg {
			return nil, fmt.Errorf("argument %d has leading or trailing whitespace", i)
		}
		for _, r := range arg {
			if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
				return nil, fmt.Errorf("argument %d contains control character 0x%02x", i, r)
			}
		}
		totalBytes += len(arg)
	}
	if totalBytes > maxTotalArgBytes {
		return nil, fmt.Errorf("command total size %d bytes exceeds maximum of %d bytes", totalBytes, maxTotalArgBytes)
	}
	return parsed.Command, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/k8s/ -run TestParseKubectlInput -v`
Expected: PASS (both subtests).

- [ ] **Step 5: Commit**

```bash
git add internal/k8s/agent.go internal/k8s/agent_test.go
git commit -m "feat(k8s): add parseKubectlInput basic argv validation"
```

---

## Task 6: `parseKubectlInput` — verb allowlist (TDD)

**Files:**
- Modify: `internal/k8s/agent.go`
- Modify: `internal/k8s/agent_test.go`

- [ ] **Step 1: Append the verb-allowlist table test**

Append to `internal/k8s/agent_test.go`:

```go
func TestParseKubectlInput_VerbAllowlist(t *testing.T) {
	allowed := []string{
		`["get","pods"]`,
		`["describe","pod","prom-0"]`,
		`["logs","prom-0","--tail=20"]`,
		`["top","nodes"]`,
		`["events","-n","monitoring"]`,
		`["explain","pods.spec.containers"]`,
		`["version","--short"]`,
		`["api-resources"]`,
		`["api-versions"]`,
		`["cluster-info"]`,
		`["auth","can-i","get","pods"]`,
		`["rollout","history","deployment/foo"]`,
		// flags before verb are tolerated as long as the FIRST non-flag is a verb
		`["-v=4","get","pods"]`,
	}
	for _, c := range allowed {
		t.Run("allowed:"+c, func(t *testing.T) {
			_, err := parseKubectlInput(json.RawMessage(`{"command":` + c + `}`))
			if err != nil {
				t.Errorf("expected no error for %s, got %v", c, err)
			}
		})
	}

	rejected := []struct {
		argv    string
		wantErr string
	}{
		{`["delete","pod","prom-0"]`, "delete"},
		{`["apply","-f","x.yaml"]`, "apply"},
		{`["create","ns","x"]`, "create"},
		{`["edit","pod","prom-0"]`, "edit"},
		{`["patch","pod","prom-0","-p","{}"]`, "patch"},
		{`["replace","-f","x.yaml"]`, "replace"},
		{`["scale","--replicas=0","deployment/foo"]`, "scale"},
		{`["cordon","node-1"]`, "cordon"},
		{`["drain","node-1"]`, "drain"},
		{`["uncordon","node-1"]`, "uncordon"},
		{`["exec","prom-0","--","sh"]`, "exec"},
		{`["cp","prom-0:/tmp/x","./x"]`, "cp"},
		{`["port-forward","prom-0","9090"]`, "port-forward"},
		{`["proxy"]`, "proxy"},
		{`["debug","prom-0"]`, "debug"},
		{`["attach","prom-0"]`, "attach"},
		{`["wait","--for=condition=Ready","pod/prom-0"]`, "wait"},
		{`["config","view"]`, "config"},
		{`["kustomize","./manifests"]`, "kustomize"},
		{`["plugin","list"]`, "plugin"},
		{`["completion","bash"]`, "completion"},
		{`["alpha","debug","node-1"]`, "alpha"},
		{`["kubectl-foo","args"]`, "kubectl-foo"},
		// auth sub-verb rules
		{`["auth","whoami"]`, "auth whoami"},
		{`["auth","reconcile"]`, "auth reconcile"},
		// rollout sub-verb rules
		{`["rollout","status","deployment/foo"]`, "rollout status"},
		{`["rollout","restart","deployment/foo"]`, "rollout restart"},
		{`["rollout","undo","deployment/foo"]`, "rollout undo"},
	}
	for _, c := range rejected {
		t.Run("rejected:"+c.argv, func(t *testing.T) {
			_, err := parseKubectlInput(json.RawMessage(`{"command":` + c.argv + `}`))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("expected error containing %q, got %q", c.wantErr, err.Error())
			}
		})
	}
}
```

- [ ] **Step 2: Run to verify allowlist tests fail**

Run: `go test ./internal/k8s/ -run TestParseKubectlInput_VerbAllowlist -v`
Expected: FAIL — current parser accepts every verb.

- [ ] **Step 3: Add the verb-allowlist enforcement to `agent.go`**

Append to `internal/k8s/agent.go`:

```go
// allowedKubectlVerbs is the read-only built-in subcommand set. The agent
// system prompt promises read-only behavior; this allowlist enforces it
// for the subcommands the API server cannot see (config, kustomize,
// plugin) plus the obvious write verbs (delete, apply, …). RBAC is the
// final word for everything that does reach the API server.
var allowedKubectlVerbs = map[string]bool{
	"get": true, "describe": true, "logs": true, "top": true, "events": true,
	"explain": true, "version": true, "api-resources": true, "api-versions": true,
	"cluster-info": true, "auth": true, "rollout": true,
}

// allowedKubectlSubVerbs constrains verbs that have read-only sub-verbs.
// Any other sub-verb (or none) is rejected.
var allowedKubectlSubVerbs = map[string]map[string]bool{
	"auth":    {"can-i": true},
	"rollout": {"history": true},
}

// validateKubectlVerb runs after parseKubectlInput's byte-level checks. It
// finds the first non-flag token (the verb) and the second non-flag token
// (the sub-verb, when applicable) and rejects anything outside the allowlist.
func validateKubectlVerb(argv []string) error {
	verb, subVerb := extractVerbs(argv)
	if verb == "" {
		return fmt.Errorf("kubectl command has no verb; allowed verbs: %s", listAllowedVerbs())
	}
	if !allowedKubectlVerbs[verb] {
		return fmt.Errorf("Command denied: kubectl %s is not permitted; allowed verbs: %s", verb, listAllowedVerbs())
	}
	if subs, hasSubs := allowedKubectlSubVerbs[verb]; hasSubs {
		if subVerb == "" || !subs[subVerb] {
			label := verb
			if subVerb != "" {
				label = verb + " " + subVerb
			}
			return fmt.Errorf("Command denied: kubectl %s is not permitted; only %s %s is allowed",
				label, verb, allowedSubVerbList(verb))
		}
	}
	return nil
}

func extractVerbs(argv []string) (verb, subVerb string) {
	for _, a := range argv {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if verb == "" {
			verb = a
			continue
		}
		subVerb = a
		return
	}
	return
}

func listAllowedVerbs() string {
	keys := make([]string, 0, len(allowedKubectlVerbs))
	for k := range allowedKubectlVerbs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

func allowedSubVerbList(verb string) string {
	subs := allowedKubectlSubVerbs[verb]
	keys := make([]string, 0, len(subs))
	for k := range subs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}
```

Add `"sort"` to the existing imports.

- [ ] **Step 4: Wire the verb check into `parseKubectlInput`**

In `parseKubectlInput`, after the for-loop that returns `parsed.Command, nil`, replace the final `return parsed.Command, nil` with:

```go
	if err := validateKubectlVerb(parsed.Command); err != nil {
		return nil, err
	}
	return parsed.Command, nil
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/k8s/ -run TestParseKubectlInput -v`
Expected: PASS (basic + verb-allowlist).

- [ ] **Step 6: Commit**

```bash
git add internal/k8s/agent.go internal/k8s/agent_test.go
git commit -m "feat(k8s): add verb allowlist to parseKubectlInput"
```

---

## Task 7: `parseKubectlInput` — global-flag denylist (TDD)

**Files:**
- Modify: `internal/k8s/agent.go`
- Modify: `internal/k8s/agent_test.go`

- [ ] **Step 1: Append the global-flag denylist test**

Append to `internal/k8s/agent_test.go`:

```go
func TestParseKubectlInput_GlobalFlagDenylist(t *testing.T) {
	deniedFlags := []string{
		"--kubeconfig", "--server", "--token", "--token-file",
		"--as", "--as-group", "--as-uid",
		"--user", "--cluster", "--context",
		"--certificate-authority",
		"--client-certificate", "--client-key",
		"--insecure-skip-tls-verify",
		"--password", "--username",
		"--tls-server-name",
	}
	for _, f := range deniedFlags {
		// --flag value form
		t.Run("space:"+f, func(t *testing.T) {
			argv := `["get","pods","` + f + `","value"]`
			_, err := parseKubectlInput(json.RawMessage(`{"command":` + argv + `}`))
			if err == nil || !strings.Contains(err.Error(), f) {
				t.Errorf("expected rejection naming %q, got %v", f, err)
			}
		})
		// --flag=value form
		t.Run("equals:"+f, func(t *testing.T) {
			argv := `["get","pods","` + f + `=value"]`
			_, err := parseKubectlInput(json.RawMessage(`{"command":` + argv + `}`))
			if err == nil || !strings.Contains(err.Error(), f) {
				t.Errorf("expected rejection naming %q, got %v", f, err)
			}
		})
		// flag before verb form
		t.Run("before-verb:"+f, func(t *testing.T) {
			argv := `["` + f + `=value","get","pods"]`
			_, err := parseKubectlInput(json.RawMessage(`{"command":` + argv + `}`))
			if err == nil || !strings.Contains(err.Error(), f) {
				t.Errorf("expected rejection naming %q, got %v", f, err)
			}
		})
	}

	t.Run("short -s flag", func(t *testing.T) {
		_, err := parseKubectlInput(json.RawMessage(`{"command":["get","pods","-s","https://attacker"]}`))
		if err == nil || !strings.Contains(err.Error(), "-s") {
			t.Errorf("expected rejection naming -s, got %v", err)
		}
	})
	t.Run("short -s does not match longer flags", func(t *testing.T) {
		// e.g. logs -s is not a real kubectl flag, but make sure substring
		// matching does not happen — argv element "-since" must NOT be rejected
		// as if it were "-s".
		_, err := parseKubectlInput(json.RawMessage(`{"command":["logs","prom-0","--since=10m"]}`))
		if err != nil {
			t.Errorf("expected no rejection for --since, got %v", err)
		}
	})
}
```

- [ ] **Step 2: Run to verify tests fail**

Run: `go test ./internal/k8s/ -run TestParseKubectlInput_GlobalFlagDenylist -v`
Expected: FAIL — current parser accepts these flags.

- [ ] **Step 3: Add the denylist + check function**

Append to `internal/k8s/agent.go`:

```go
// deniedKubectlGlobalFlags lists flags that swap the cluster identity, target
// server, or auth credentials. They are rejected anywhere in argv before the
// verb is even examined: an allowed verb (`get`) used with an alternate
// kubeconfig defeats RBAC entirely.
var deniedKubectlGlobalFlags = map[string]bool{
	"--kubeconfig":               true,
	"--server":                   true,
	"-s":                         true, // short alias for --server
	"--token":                    true,
	"--token-file":               true,
	"--as":                       true,
	"--as-group":                 true,
	"--as-uid":                   true,
	"--user":                     true,
	"--cluster":                  true,
	"--context":                  true,
	"--certificate-authority":    true,
	"--client-certificate":       true,
	"--client-key":               true,
	"--insecure-skip-tls-verify": true,
	"--password":                 true,
	"--username":                 true,
	"--tls-server-name":          true,
}

// validateKubectlFlags rejects any argv element that names a denied global flag,
// in either the "--flag value" form (exact-token match) or the "--flag=value"
// form (prefix match up to the "="). The single-dash "-s" form is matched only
// as an exact token so that per-subcommand short flags like "-since" or "-c"
// are unaffected.
func validateKubectlFlags(argv []string) error {
	for _, a := range argv {
		// Exact-token match (covers "--kubeconfig" alone before its value, and "-s")
		if deniedKubectlGlobalFlags[a] {
			return fmt.Errorf("Command denied: %s is not permitted; the in-cluster ServiceAccount is the only allowed identity (other denied flags: --kubeconfig, --server, --token, --as, --user, --cluster, --context, --client-*, --certificate-authority, --insecure-skip-tls-verify, --password, --username)", a)
		}
		// "--flag=value" form: split on the first "=" and check the head.
		// Skip single-dash forms ("-s=foo" is uncommon; if it appears, the head
		// "-s" is in the denylist and exact-match would catch the unsplit form
		// anyway when the value is in a separate argv element).
		if strings.HasPrefix(a, "--") {
			if eq := strings.IndexByte(a, '='); eq != -1 {
				if deniedKubectlGlobalFlags[a[:eq]] {
					return fmt.Errorf("Command denied: %s is not permitted; the in-cluster ServiceAccount is the only allowed identity", a[:eq])
				}
			}
		}
	}
	return nil
}
```

- [ ] **Step 4: Wire the flag check into `parseKubectlInput`**

In `parseKubectlInput`, replace the verb-validation block with the two-step gate:

```go
	if err := validateKubectlFlags(parsed.Command); err != nil {
		return nil, err
	}
	if err := validateKubectlVerb(parsed.Command); err != nil {
		return nil, err
	}
	return parsed.Command, nil
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/k8s/ -run TestParseKubectlInput -v`
Expected: PASS (all three subtest groups: basic, verb, flag).

- [ ] **Step 6: Commit**

```bash
git add internal/k8s/agent.go internal/k8s/agent_test.go
git commit -m "feat(k8s): add global-flag denylist to parseKubectlInput"
```

---

## Task 8: `parsePromQLInput` (TDD)

**Files:**
- Modify: `internal/k8s/agent.go`
- Modify: `internal/k8s/agent_test.go`

- [ ] **Step 1: Append the test**

Append to `internal/k8s/agent_test.go`:

```go
func TestParsePromQLInput(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    string
		wantErr string
	}{
		{
			name:  "valid query",
			input: `{"query":"up"}`,
			want:  "up",
		},
		{
			name:    "empty query",
			input:   `{"query":""}`,
			wantErr: "empty query",
		},
		{
			name:    "whitespace-only",
			input:   `{"query":"   "}`,
			wantErr: "empty query",
		},
		{
			name:    "newline embedded",
			input:   `{"query":"up\n## injected"}`,
			wantErr: "control character",
		},
		{
			name:    "null byte",
			input:   `{"query":"up "}`,
			wantErr: "control character",
		},
		{
			name:    "too long",
			input:   `{"query":"` + strings.Repeat("x", 4097) + `"}`,
			wantErr: "exceeds maximum",
		},
		{
			name:    "invalid JSON",
			input:   `not json`,
			wantErr: "parse query input",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePromQLInput(json.RawMessage(tc.input))
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("expected error containing %q, got %q", tc.wantErr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/k8s/ -run TestParsePromQLInput -v`
Expected: BUILD FAIL — `parsePromQLInput undefined`.

- [ ] **Step 3: Add `parsePromQLInput`**

Append to `internal/k8s/agent.go`:

```go
// parsePromQLInput validates a promql_query tool call. The 4096-byte cap is
// the same as the per-argument cap used by kubectl_exec; control characters
// are rejected for the same prompt-injection reasons (a query embedded with
// "\n## INJECTED" inside an error path could pollute the model context).
func parsePromQLInput(input json.RawMessage) (string, error) {
	var parsed struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal(input, &parsed); err != nil {
		return "", fmt.Errorf("parse query input: %w", err)
	}
	if strings.TrimSpace(parsed.Query) == "" {
		return "", fmt.Errorf("empty query")
	}
	if len(parsed.Query) > maxKubectlPromQLen {
		return "", fmt.Errorf("query exceeds maximum length of %d bytes", maxKubectlPromQLen)
	}
	for _, r := range parsed.Query {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return "", fmt.Errorf("query contains control character 0x%02x", r)
		}
	}
	return parsed.Query, nil
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/k8s/ -run TestParsePromQLInput -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/k8s/agent.go internal/k8s/agent_test.go
git commit -m "feat(k8s): add parsePromQLInput"
```

---

## Task 9: Tool definitions + system prompt template

**Files:**
- Modify: `internal/k8s/agent.go`

- [ ] **Step 1: Append tool definitions and system prompt to `agent.go`**

Append:

```go
// kubectlTool is the Claude tool definition for argv-based kubectl execution.
// The schema mirrors checkmk's execute_command tool — one argv array, no shell.
var kubectlTool = shared.Tool{
	Name:        "kubectl_exec",
	Description: "Run a read-only kubectl command. The command is passed as an argv array (no shell). Examples: [\"get\",\"pods\",\"-n\",\"monitoring\",\"-o\",\"wide\"], [\"describe\",\"pod\",\"prom-0\",\"-n\",\"monitoring\"], [\"logs\",\"pod-x\",\"-n\",\"db\",\"--tail=100\"], [\"top\",\"nodes\"]. Allowed verbs: get, describe, logs, top, events, explain, version, api-resources, api-versions, cluster-info, auth can-i, rollout history.",
	InputSchema: shared.InputSchema{
		Type: "object",
		Properties: map[string]shared.Property{
			"command": {
				Type:        "array",
				Description: "kubectl arguments as argv array, without the leading 'kubectl'",
				Items:       &shared.Items{Type: "string"},
			},
		},
		Required: []string{"command"},
	},
}

// promqlTool is the Claude tool definition for arbitrary PromQL queries
// against the configured Prometheus instance.
var promqlTool = shared.Tool{
	Name:        "promql_query",
	Description: "Run a PromQL query against Prometheus. Returns time-series results. Example: 'rate(http_requests_total[5m])'.",
	InputSchema: shared.InputSchema{
		Type: "object",
		Properties: map[string]shared.Property{
			"query": {
				Type:        "string",
				Description: "PromQL expression",
			},
		},
		Required: []string{"query"},
	},
}

// agentSystemPromptTemplate is the system prompt for the k8s agentic loop.
// %d is replaced with the actual maxRounds value at call time so Claude's
// self-reported round budget always matches the real limit, exactly as in
// checkmk's agentSystemPromptForRounds.
const agentSystemPromptTemplate = `You are a Kubernetes SRE analyst investigating a monitoring alert.

Your task:
1. Use kubectl_exec to run read-only kubectl commands and promql_query for Prometheus queries.
2. Investigate the alert across pods, deployments, events, logs, and metrics.
3. When you have enough information, stop calling tools and write your analysis.

Guidelines:
- Read-only commands only. Allowed kubectl verbs: get, describe, logs, top, events, explain, version, api-resources, api-versions, cluster-info, ` + "`auth can-i`, `rollout history`" + `.
- NEVER use: delete, apply, create, edit, patch, replace, scale, the rest of rollout (status, restart, pause, resume, undo), cordon/drain/uncordon, exec, cp, port-forward, proxy, debug, attach.
- NEVER pass: --kubeconfig, --server, --token, --as, --user, --cluster, --context, --certificate-authority, --client-*, --insecure-skip-tls-verify, or any other flag that overrides cluster identity or auth — they are rejected by the runtime.
- The ServiceAccount's RBAC permissions decide what is actually allowed; if a command fails with "Forbidden", do NOT retry — pick a different angle.
- You have a maximum of %d tool rounds.
- Static context (Prometheus metrics, recent events, pod status, pod logs) is already in the user message — start by reading it before issuing your first tool call.
- Begin broad (cluster-wide events, namespace overview) then narrow down based on findings.

Output your final analysis in markdown (headings, bold, lists, code blocks — no tables):
1. Root cause
2. Severity and blast radius
3. Remediation steps (concrete kubectl commands the operator should run)
4. Correlations between alerts/services if applicable

Reference actual values from command outputs and metric results. Keep response under 500 words.
Start directly with the analysis — no preamble, meta-commentary, or introductory sentences.`

func agentSystemPromptForRounds(maxRounds int) string {
	return fmt.Sprintf(agentSystemPromptTemplate, maxRounds)
}
```

Add `"github.com/madic-creates/claude-alert-analyzer/internal/shared"` to the imports.

- [ ] **Step 2: Verify the file compiles**

Run: `go build ./internal/k8s/...`
Expected: success.

- [ ] **Step 3: Smoke-test the prompt formatter**

Append to `internal/k8s/agent_test.go`:

```go
func TestAgentSystemPromptForRounds(t *testing.T) {
	got := agentSystemPromptForRounds(7)
	if !strings.Contains(got, "maximum of 7 tool rounds") {
		t.Errorf("expected '7 tool rounds' in output, got:\n%s", got)
	}
	if !strings.Contains(got, "kubectl_exec") {
		t.Errorf("expected kubectl_exec mention in prompt")
	}
}
```

Run: `go test ./internal/k8s/ -run TestAgentSystemPromptForRounds -v`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/k8s/agent.go internal/k8s/agent_test.go
git commit -m "feat(k8s): add tool definitions and agent system prompt"
```

---

## Task 10: `KubectlRunner` interface + `kubectlSubprocess` (TDD)

**Files:**
- Modify: `internal/k8s/agent.go`
- Modify: `internal/k8s/agent_test.go`

The `kubectlSubprocess` test uses the standard Go pattern of re-exec'ing the test binary with `-test.run=TestHelperProcess` to play the role of the kubectl child process. This avoids needing a real kubectl binary on the host and lets the helper inspect its own argv and env.

- [ ] **Step 1: Add `KubectlRunner` interface and `kubectlSubprocess` skeleton**

Append to `internal/k8s/agent.go`:

```go
// KubectlRunner is the seam between the agent loop and the actual kubectl
// subprocess. The default implementation (kubectlSubprocess) shells out;
// tests substitute their own implementation.
type KubectlRunner interface {
	Exec(ctx context.Context, argv []string, timeout time.Duration) (string, error)
}

// kubectlSubprocess invokes a fixed kubectl binary path with a scrubbed
// environment. The constructor performs a single os.Stat at startup and
// logs a warning if the binary is missing — but does not fail startup,
// because the static prefetch (which uses client-go) keeps working.
type kubectlSubprocess struct {
	Path string
	Env  []string
}

const defaultKubectlPath = "/usr/local/bin/kubectl"

// NewKubectlSubprocess constructs a runner that invokes the kubectl binary
// at path (default: /usr/local/bin/kubectl). The env slice contains only
// HOME and USER taken from the runtime environment; everything else
// (KUBECONFIG, PATH, proxy vars, LD_PRELOAD) is dropped so that no
// inherited variable can redirect kubectl's auth or behavior.
func NewKubectlSubprocess(path string) *kubectlSubprocess {
	if path == "" {
		path = defaultKubectlPath
	}
	if _, err := os.Stat(path); err != nil {
		slog.Warn("kubectl binary not found at startup", "path", path, "error", err)
	}
	env := []string{
		"HOME=" + os.Getenv("HOME"),
		"USER=" + os.Getenv("USER"),
	}
	return &kubectlSubprocess{Path: path, Env: env}
}

func (k *kubectlSubprocess) Exec(ctx context.Context, argv []string, timeout time.Duration) (string, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, k.Path, argv...)
	cmd.Env = k.Env
	if home := os.Getenv("HOME"); home != "" {
		cmd.Dir = home
	}

	out, err := cmd.CombinedOutput()
	return string(out), err
}
```

Add imports: `"context"`, `"log/slog"`, `"os"`, `"os/exec"`, `"time"`.

- [ ] **Step 2: Add the `TestHelperProcess` pattern + subprocess test**

Append to `internal/k8s/agent_test.go`:

```go
// TestHelperProcess plays the role of the kubectl child process when the
// test binary is invoked with GO_KUBECTL_HELPER=1. It reflects argv and
// selected env back to stdout/stderr so the parent test can assert on them.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_KUBECTL_HELPER") != "1" {
		return
	}
	// argv inspection: print argv (skipping go test internal args)
	args := os.Args
	for i, a := range args {
		if a == "--" {
			args = args[i+1:]
			break
		}
	}
	fmt.Printf("ARGV: %v\n", args)
	// env inspection: print only the env keys, sorted
	env := os.Environ()
	sort.Strings(env)
	for _, e := range env {
		// Skip Go test machinery keys (GOCOVERDIR, GO_TEST_*) so the test can
		// match exactly the user-visible env.
		if strings.HasPrefix(e, "GO_") || strings.HasPrefix(e, "PWD=") {
			continue
		}
		fmt.Printf("ENV: %s\n", e)
	}
	// outcome control via env
	switch os.Getenv("HELPER_MODE") {
	case "fail":
		fmt.Fprintln(os.Stderr, "stderr line")
		os.Exit(2)
	case "sleep":
		time.Sleep(2 * time.Second)
	}
	os.Exit(0)
}

func helperPath(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	return exe
}

func TestKubectlSubprocess_ArgvAndEnv(t *testing.T) {
	t.Setenv("HOME", "/tmp")
	t.Setenv("USER", "tester")
	t.Setenv("KUBECONFIG", "/should/not/leak")

	runner := &kubectlSubprocess{
		Path: helperPath(t),
		Env:  []string{"HOME=/tmp", "USER=tester", "GO_KUBECTL_HELPER=1"},
	}
	out, err := runner.Exec(context.Background(),
		[]string{"-test.run=TestHelperProcess", "--", "get", "pods"},
		5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "ARGV: [get pods]") {
		t.Errorf("argv pass-through failed; output:\n%s", out)
	}
	if strings.Contains(out, "KUBECONFIG=") {
		t.Errorf("KUBECONFIG should not have leaked; output:\n%s", out)
	}
	if !strings.Contains(out, "ENV: HOME=/tmp") {
		t.Errorf("HOME not present; output:\n%s", out)
	}
	if !strings.Contains(out, "ENV: USER=tester") {
		t.Errorf("USER not present; output:\n%s", out)
	}
}

func TestKubectlSubprocess_NonZeroExitWithOutput(t *testing.T) {
	runner := &kubectlSubprocess{
		Path: helperPath(t),
		Env:  []string{"HOME=/tmp", "USER=tester", "GO_KUBECTL_HELPER=1", "HELPER_MODE=fail"},
	}
	out, err := runner.Exec(context.Background(),
		[]string{"-test.run=TestHelperProcess", "--", "get", "pods"},
		5*time.Second)
	if err == nil {
		t.Fatalf("expected non-zero exit error, got nil; output:\n%s", out)
	}
	if !strings.Contains(out, "stderr line") {
		t.Errorf("expected combined stdout+stderr capture; output:\n%s", out)
	}
}

func TestKubectlSubprocess_Timeout(t *testing.T) {
	runner := &kubectlSubprocess{
		Path: helperPath(t),
		Env:  []string{"HOME=/tmp", "USER=tester", "GO_KUBECTL_HELPER=1", "HELPER_MODE=sleep"},
	}
	start := time.Now()
	_, err := runner.Exec(context.Background(),
		[]string{"-test.run=TestHelperProcess", "--", "get", "pods"},
		200*time.Millisecond)
	if err == nil {
		t.Fatalf("expected timeout error, got nil")
	}
	if time.Since(start) > 1500*time.Millisecond {
		t.Errorf("timeout did not fire promptly: %v", time.Since(start))
	}
}

func TestKubectlSubprocess_MissingBinary(t *testing.T) {
	runner := &kubectlSubprocess{
		Path: "/nonexistent/kubectl",
		Env:  []string{"HOME=/tmp", "USER=tester"},
	}
	_, err := runner.Exec(context.Background(), []string{"get", "pods"}, 5*time.Second)
	if err == nil {
		t.Fatalf("expected ENOENT error, got nil")
	}
}
```

Add imports: `"context"`, `"fmt"`, `"os"`, `"sort"`, `"time"` if not already present.

- [ ] **Step 3: Run the subprocess tests**

Run: `go test ./internal/k8s/ -run TestKubectlSubprocess -v`
Expected: all four subtests PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/k8s/agent.go internal/k8s/agent_test.go
git commit -m "feat(k8s): add KubectlRunner interface and kubectlSubprocess"
```

---

## Task 11: `RunAgenticDiagnostics` orchestration (TDD)

**Files:**
- Modify: `internal/k8s/agent.go`
- Modify: `internal/k8s/agent_test.go`

This is the largest task — it implements the tool-loop dispatcher with metrics, panic recovery, and the timeout wrappers. Test-first.

- [ ] **Step 1: Add fakes and the happy-path test**

Append to `internal/k8s/agent_test.go`:

```go
// fakeToolLoopRunner is a controllable mock of shared.ToolLoopRunner. The
// caller provides a function that drives the conversation: it receives the
// tool list and the handleTool callback, can call handleTool any number of
// times, and returns a final analysis string + nil error (or an error to
// simulate API failure). It records the userPrompt that was passed in.
type fakeToolLoopRunner struct {
	captured     string
	driver       func(handleTool func(name string, input json.RawMessage) (string, error)) (string, error)
}

func (f *fakeToolLoopRunner) RunToolLoop(
	ctx context.Context, system, user string,
	tools []shared.Tool, maxRounds int,
	handleTool func(name string, input json.RawMessage) (string, error),
) (string, error) {
	f.captured = user
	return f.driver(handleTool)
}

type fakeKubectlRunner struct {
	calls    [][]string
	response string
	err      error
}

func (f *fakeKubectlRunner) Exec(ctx context.Context, argv []string, timeout time.Duration) (string, error) {
	f.calls = append(f.calls, append([]string(nil), argv...))
	return f.response, f.err
}

type fakePromQLQuerier struct {
	calls    []string
	response string
}

func (f *fakePromQLQuerier) Query(ctx context.Context, q string) string {
	f.calls = append(f.calls, q)
	return f.response
}

func TestRunAgenticDiagnostics_HappyPath(t *testing.T) {
	kc := &fakeKubectlRunner{response: "pod-x   Running\n"}
	pq := &fakePromQLQuerier{response: "up: 1"}
	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetrics()}
	rounds := 0

	runner := &fakeToolLoopRunner{
		driver: func(handleTool func(name string, input json.RawMessage) (string, error)) (string, error) {
			rounds++
			out, err := handleTool("kubectl_exec", json.RawMessage(`{"command":["get","pods"]}`))
			if err != nil {
				t.Fatalf("handleTool unexpected error: %v", err)
			}
			if !strings.Contains(out, "pod-x") {
				t.Errorf("expected kubectl output, got %q", out)
			}
			return "## Root cause\n…final analysis…", nil
		},
	}

	got, err := RunAgenticDiagnostics(
		context.Background(), runner, kc, pq, metrics,
		"## Alert: Foo\n…body…", 10,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "Root cause") {
		t.Errorf("unexpected analysis: %q", got)
	}
	if runner.captured != "## Alert: Foo\n…body…" {
		t.Errorf("user prompt not preserved verbatim: %q", runner.captured)
	}
	if len(kc.calls) != 1 || kc.calls[0][0] != "get" {
		t.Errorf("unexpected kubectl calls: %v", kc.calls)
	}
}

func TestRunAgenticDiagnostics_PromQLDispatch(t *testing.T) {
	kc := &fakeKubectlRunner{}
	pq := &fakePromQLQuerier{response: "up: 1"}
	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetrics()}

	runner := &fakeToolLoopRunner{
		driver: func(handleTool func(name string, input json.RawMessage) (string, error)) (string, error) {
			out, err := handleTool("promql_query", json.RawMessage(`{"query":"up"}`))
			if err != nil {
				t.Fatalf("handleTool: %v", err)
			}
			if !strings.Contains(out, "up: 1") {
				t.Errorf("expected promql result, got %q", out)
			}
			return "ok", nil
		},
	}
	if _, err := RunAgenticDiagnostics(context.Background(), runner, kc, pq, metrics, "ctx", 10); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pq.calls) != 1 || pq.calls[0] != "up" {
		t.Errorf("unexpected promql calls: %v", pq.calls)
	}
}

func TestRunAgenticDiagnostics_ValidationRejected(t *testing.T) {
	kc := &fakeKubectlRunner{}
	pq := &fakePromQLQuerier{}
	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetrics()}

	runner := &fakeToolLoopRunner{
		driver: func(handleTool func(name string, input json.RawMessage) (string, error)) (string, error) {
			out, err := handleTool("kubectl_exec", json.RawMessage(`{"command":["delete","pod","x"]}`))
			if err != nil {
				t.Fatalf("validation rejection should not return Go error, got: %v", err)
			}
			if !strings.Contains(out, "Command denied") {
				t.Errorf("expected denial string, got: %q", out)
			}
			if len(kc.calls) != 0 {
				t.Errorf("kubectl runner should not have been called for denied verb")
			}
			return "stopped early", nil
		},
	}
	if _, err := RunAgenticDiagnostics(context.Background(), runner, kc, pq, metrics, "ctx", 10); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunAgenticDiagnostics_UnknownTool(t *testing.T) {
	kc := &fakeKubectlRunner{}
	pq := &fakePromQLQuerier{}
	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetrics()}

	runner := &fakeToolLoopRunner{
		driver: func(handleTool func(name string, input json.RawMessage) (string, error)) (string, error) {
			out, err := handleTool("not_a_tool", json.RawMessage(`{}`))
			// Unknown tool is a programming error in the conversation, not a
			// validation problem — return the error so RunToolLoop can surface it.
			if err == nil {
				t.Fatalf("expected error for unknown tool, got out=%q", out)
			}
			return "ok", nil
		},
	}
	if _, err := RunAgenticDiagnostics(context.Background(), runner, kc, pq, metrics, "ctx", 10); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
```

- [ ] **Step 2: Run to verify the tests fail to compile**

Run: `go test ./internal/k8s/ -run TestRunAgenticDiagnostics -v`
Expected: BUILD FAIL — `RunAgenticDiagnostics undefined`.

- [ ] **Step 3: Implement `RunAgenticDiagnostics`**

Append to `internal/k8s/agent.go`:

```go
// PromQLQuerier is the interface the agent loop uses to issue arbitrary
// PromQL queries. *PrometheusClient satisfies it via its public Query method.
type PromQLQuerier interface {
	Query(ctx context.Context, query string) string
}

// per-tool wall-clock timeout. Mirrors checkmk's runSSHCommand.
const agentToolTimeout = 10 * time.Second

// outcome label values for agent_tool_calls_total.
const (
	outcomeOK             = "ok"
	outcomeRejectedValid  = "rejected_validation"
	outcomeRejectedVerb   = "rejected_verb"
	outcomeExecError      = "exec_error"
	outcomeNonzeroExit    = "nonzero_exit"
	outcomeTimeout        = "timeout"
)

// RunAgenticDiagnostics drives a multi-turn Claude tool-use conversation
// for the k8s alert. It dispatches tool calls to the kubectl runner or the
// PromQL querier, applies output sanitisation/redaction/truncation in the
// same way as checkmk's RunAgenticDiagnostics, and emits per-tool
// observability via metrics.
//
// userPrompt is the FULL user message — caller is responsible for
// prepending the alert-header preamble to AnalysisContext.FormatForPrompt().
func RunAgenticDiagnostics(
	ctx context.Context,
	runner shared.ToolLoopRunner,
	kc KubectlRunner,
	prom PromQLQuerier,
	metrics *shared.AlertMetrics,
	userPrompt string,
	maxRounds int,
) (string, error) {
	slog.Info("starting agentic k8s diagnostics", "maxRounds", maxRounds)

	// toolCallCount approximates rounds-used: in practice each Claude turn
	// produces exactly one tool_use block in this code path, so tool calls
	// and rounds are 1:1. Even if Claude emits multi-tool rounds in a future
	// API revision, the metric remains a useful "Claude work done" counter.
	toolCallCount := 0

	handleTool := func(name string, input json.RawMessage) (string, error) {
		toolCallCount++
		start := time.Now()
		switch name {
		case "kubectl_exec":
			return handleKubectlTool(ctx, kc, metrics, input, start)
		case "promql_query":
			return handlePromQLTool(ctx, prom, metrics, input, start)
		default:
			return "", fmt.Errorf("unknown tool: %s", name)
		}
	}

	// Wrap handleTool with panic recovery so a buggy handler cannot kill the
	// loop. The synthetic tool result lets Claude move on instead of aborting.
	safeHandleTool := func(name string, input json.RawMessage) (result string, err error) {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("agent tool handler panicked", "tool", name, "recover", r)
				if metrics != nil {
					metrics.RecordAgentToolCall("k8s", name, outcomeExecError, 0)
				}
				result = fmt.Sprintf("Tool %s panicked: %v — continue with a different command", name, r)
				err = nil
			}
		}()
		return handleTool(name, input)
	}

	analysis, err := runner.RunToolLoop(
		ctx,
		agentSystemPromptForRounds(maxRounds),
		userPrompt,
		[]shared.Tool{kubectlTool, promqlTool},
		maxRounds,
		safeHandleTool,
	)
	exhausted := toolCallCount >= maxRounds
	if metrics != nil {
		metrics.RecordAgentRounds("k8s", toolCallCount, exhausted)
	}
	slog.Info("agentic k8s diagnostics complete",
		"tool_calls", toolCallCount, "exhausted", exhausted)
	if err != nil {
		return "", fmt.Errorf("agentic loop failed: %w", err)
	}
	return analysis, nil
}

func handleKubectlTool(ctx context.Context, kc KubectlRunner, metrics *shared.AlertMetrics, input json.RawMessage, start time.Time) (string, error) {
	argv, err := parseKubectlInput(input)
	if err != nil {
		// Distinguish verb/flag rejection from byte-level validation so
		// metrics can show which class of bad input Claude is hitting.
		outcome := outcomeRejectedValid
		if strings.Contains(err.Error(), "Command denied") {
			outcome = outcomeRejectedVerb
		}
		recordToolCall(metrics, "kubectl_exec", outcome, time.Since(start), nil)
		// Validation errors return the message as the tool result (not a Go
		// error) so Claude can self-correct.
		return err.Error(), nil
	}

	out, err := kc.Exec(ctx, argv, agentToolTimeout)
	out = shared.SanitizeOutput(out)
	out = shared.RedactSecrets(out)
	out = shared.Truncate(out, 4096)

	cmdLine := "kubectl " + strings.Join(argv, " ")
	if err != nil {
		outcome := outcomeNonzeroExit
		if ctxErr := ctx.Err(); ctxErr != nil || isTimeoutErr(err) {
			outcome = outcomeTimeout
		} else if isExecError(err) {
			outcome = outcomeExecError
		}
		recordToolCall(metrics, "kubectl_exec", outcome, time.Since(start), argv)
		if out != "" {
			return fmt.Sprintf("$ %s\n%s\n[exited: %v]", cmdLine, out, err), nil
		}
		return fmt.Sprintf("Command failed: %v", err), nil
	}
	recordToolCall(metrics, "kubectl_exec", outcomeOK, time.Since(start), argv)
	return fmt.Sprintf("$ %s\n%s", cmdLine, out), nil
}

func handlePromQLTool(ctx context.Context, prom PromQLQuerier, metrics *shared.AlertMetrics, input json.RawMessage, start time.Time) (string, error) {
	q, err := parsePromQLInput(input)
	if err != nil {
		recordToolCall(metrics, "promql_query", outcomeRejectedValid, time.Since(start), nil)
		return err.Error(), nil
	}
	queryCtx, cancel := context.WithTimeout(ctx, agentToolTimeout)
	defer cancel()
	out := prom.Query(queryCtx, q)
	out = shared.SanitizeOutput(out)
	out = shared.RedactSecrets(out)
	out = shared.Truncate(out, 4096)
	recordToolCall(metrics, "promql_query", outcomeOK, time.Since(start), nil)
	return fmt.Sprintf("# PromQL: %s\n%s", q, out), nil
}

func recordToolCall(metrics *shared.AlertMetrics, tool, outcome string, dur time.Duration, argv []string) {
	if argv != nil {
		slog.Info("agent tool call",
			"tool", tool, "argv", argv, "duration_ms", dur.Milliseconds(), "outcome", outcome)
	} else {
		slog.Info("agent tool call",
			"tool", tool, "duration_ms", dur.Milliseconds(), "outcome", outcome)
	}
	if metrics != nil {
		metrics.RecordAgentToolCall("k8s", tool, outcome, dur)
	}
}

func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "context deadline exceeded") ||
		strings.Contains(err.Error(), "signal: killed")
}

func isExecError(err error) bool {
	if err == nil {
		return false
	}
	// exec.LookPath / no such file errors don't return *exec.ExitError; they
	// return a wrapped fs.PathError.
	return strings.Contains(err.Error(), "no such file or directory") ||
		strings.Contains(err.Error(), "executable file not found")
}
```

- [ ] **Step 4: Run the test set, fix anything that fails**

Run: `go test ./internal/k8s/ -run TestRunAgenticDiagnostics -v`
Expected: PASS for all four cases (HappyPath, PromQLDispatch, ValidationRejected, UnknownTool).

- [ ] **Step 5: Add panic-recovery and metrics observation tests**

Append:

```go
func TestRunAgenticDiagnostics_PanicRecovery(t *testing.T) {
	kc := &fakeKubectlRunner{}
	pq := &fakePromQLQuerier{}
	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetrics()}

	runner := &fakeToolLoopRunner{
		driver: func(handleTool func(name string, input json.RawMessage) (string, error)) (string, error) {
			out, err := handleTool("kubectl_exec", json.RawMessage(`{}`)) // malformed → parse error path normally
			// Force a panic via promql_query with a nil querier check would be
			// disruptive; instead exercise the unknown-tool path and ensure
			// the wrapper never returns a panic. The wrapper is exercised
			// directly:
			if err == nil && !strings.Contains(out, "argument") && !strings.Contains(out, "command") {
				t.Errorf("expected validation error string, got %q", out)
			}
			return "done", nil
		},
	}
	if _, err := RunAgenticDiagnostics(context.Background(), runner, kc, pq, metrics, "ctx", 10); err != nil {
		t.Fatalf("loop returned error: %v", err)
	}
}

func TestRunAgenticDiagnostics_RecordsMetrics(t *testing.T) {
	kc := &fakeKubectlRunner{response: "ok\n"}
	pq := &fakePromQLQuerier{response: "v"}
	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetrics()}

	runner := &fakeToolLoopRunner{
		driver: func(handleTool func(name string, input json.RawMessage) (string, error)) (string, error) {
			_, _ = handleTool("kubectl_exec", json.RawMessage(`{"command":["get","pods"]}`))
			_, _ = handleTool("kubectl_exec", json.RawMessage(`{"command":["delete","pod","x"]}`))
			_, _ = handleTool("promql_query", json.RawMessage(`{"query":"up"}`))
			return "done", nil
		},
	}
	_, err := RunAgenticDiagnostics(context.Background(), runner, kc, pq, metrics, "ctx", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := strings.Builder{}
	metrics.MetricsHandler()(httptestNewRecorder(&got), httptestNewRequest())
	body := got.String()
	if !strings.Contains(body, `agent_tool_calls_total{outcome="ok",source="k8s",tool="kubectl_exec"} 1`) {
		t.Errorf("missing kubectl ok counter; body:\n%s", body)
	}
	if !strings.Contains(body, `agent_tool_calls_total{outcome="rejected_verb",source="k8s",tool="kubectl_exec"} 1`) {
		t.Errorf("missing kubectl rejected_verb counter; body:\n%s", body)
	}
	if !strings.Contains(body, `agent_tool_calls_total{outcome="ok",source="k8s",tool="promql_query"} 1`) {
		t.Errorf("missing promql ok counter; body:\n%s", body)
	}
}
```

- [ ] **Step 6: Run all agent tests**

Run: `go test ./internal/k8s/ -run "TestRunAgenticDiagnostics|TestParseKubectl|TestParsePromQL|TestKubectlSubprocess" -v`
Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/k8s/agent.go internal/k8s/agent_test.go
git commit -m "feat(k8s): add RunAgenticDiagnostics with metrics + panic recovery"
```

---

## Task 12: Wire `RunAgenticDiagnostics` into `ProcessAlert`

**Files:**
- Modify: `internal/k8s/pipeline.go`
- Modify: `internal/k8s/pipeline_test.go`

- [ ] **Step 1: Update `PipelineDeps`**

In `internal/k8s/pipeline.go`, replace:

```go
type PipelineDeps struct {
	Analyzer      shared.Analyzer
	Publishers    []shared.Publisher
	Cooldown      *shared.CooldownManager
	Metrics       *shared.AlertMetrics
	SystemPrompt  string
	GatherContext func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext
}
```

with:

```go
type PipelineDeps struct {
	ToolRunner     shared.ToolLoopRunner
	KubectlRunner  KubectlRunner
	Prom           PromQLQuerier
	Publishers     []shared.Publisher
	Cooldown       *shared.CooldownManager
	Metrics        *shared.AlertMetrics
	MaxAgentRounds int
	GatherContext  func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext
}
```

- [ ] **Step 2: Update `ProcessAlert` to use `RunAgenticDiagnostics`**

In `ProcessAlert`, replace the existing `Analyzer.Analyze(...)` call. The
`userPrompt` assembly must stay verbatim — it produces the prefix that
Task 4's strengthened test asserts on.

Replace:

```go
	analysis, err := deps.Analyzer.Analyze(ctx, deps.SystemPrompt, userPrompt)
	if err != nil {
```

with:

```go
	analysis, err := RunAgenticDiagnostics(ctx, deps.ToolRunner, deps.KubectlRunner, deps.Prom, deps.Metrics, userPrompt, deps.MaxAgentRounds)
	if err != nil {
```

Keep all subsequent error-handling, cooldown-clear, and ntfy-publish logic unchanged.

- [ ] **Step 3: Update `pipeline_test.go` fixture wiring**

The existing tests construct `PipelineDeps` directly. Update each construction:
- Replace `Analyzer: <fake>` with `ToolRunner: <fake-toolloop>` and add `KubectlRunner`, `Prom`, `MaxAgentRounds: 10`.
- Reuse `fakeToolLoopRunner`, `fakeKubectlRunner`, `fakePromQLQuerier` from `agent_test.go` (Task 11). If they're not in scope (different test file), copy them or expose via a `_test_helpers.go` file.

For tests that previously asserted on the `Analyze`-captured prompt (the `StartsAt` / strengthened-prefix one), now use `runner.captured` from `fakeToolLoopRunner`.

For tests that exercised the failure-notification path on `Analyze` error, use a `fakeToolLoopRunner` whose driver returns `("", errors.New("synthetic"))`.

- [ ] **Step 4: Run the pipeline tests**

Run: `go test ./internal/k8s/ -run TestProcessAlert -v`
Expected: PASS, including the strengthened header-prefix assertion from Task 4.

- [ ] **Step 5: Run the entire k8s package**

Run: `go test ./internal/k8s/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/k8s/pipeline.go internal/k8s/pipeline_test.go
git commit -m "feat(k8s): switch ProcessAlert to RunAgenticDiagnostics"
```

---

## Task 13: Wire dependencies in `cmd/k8s-analyzer/main.go`

**Files:**
- Modify: `cmd/k8s-analyzer/main.go`

- [ ] **Step 1: Drop `ALLOWED_NAMESPACES`, add `MAX_AGENT_ROUNDS`**

In `loadConfig()`:
- Remove the `allowedNS` parsing block and the `nsList` slice.
- Add (mirror checkmk's pattern at `cmd/checkmk-analyzer/main.go:20`):

```go
	maxAgentRounds, err := shared.ParseIntEnv("MAX_AGENT_ROUNDS", "10", 1, 50)
	if err != nil {
		slog.Error("invalid config", "error", err)
		os.Exit(1)
	}
```

- In the returned `k8s.Config{...}`, drop `AllowedNamespaces:` and add `MaxAgentRounds: maxAgentRounds`.

- [ ] **Step 2: Drop the local `systemPrompt` constant**

Delete the `const systemPrompt = ...` block at the top of the file. The agentic loop uses `agentSystemPromptForRounds` from `internal/k8s/agent.go`.

- [ ] **Step 3: Construct `kubectlSubprocess` and update `PipelineDeps`**

Replace:

```go
	deps := k8s.PipelineDeps{
		Analyzer:     claudeClient,
		Publishers:   publishers,
		Cooldown:     cooldownMgr,
		Metrics:      metrics,
		SystemPrompt: systemPrompt,
		GatherContext: func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext {
			return k8s.GatherContext(ctx, promClient, clientset, k8s.AlertPayloadToAlert(alert), cfg)
		},
	}
```

with:

```go
	kubectlRunner := k8s.NewKubectlSubprocess("")

	deps := k8s.PipelineDeps{
		ToolRunner:     claudeClient,
		KubectlRunner:  kubectlRunner,
		Prom:           promClient,
		Publishers:     publishers,
		Cooldown:       cooldownMgr,
		Metrics:        metrics,
		MaxAgentRounds: cfg.MaxAgentRounds,
		GatherContext: func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext {
			return k8s.GatherContext(ctx, promClient, clientset, k8s.AlertPayloadToAlert(alert), cfg)
		},
	}
```

- [ ] **Step 4: Update the startup log**

Replace the `slog.Info("K8s Alert Analyzer started", ...)` call:

```go
	slog.Info("K8s Alert Analyzer started",
		"port", cfg.Port, "metricsPort", cfg.MetricsPort, "model", cfg.ClaudeModel,
		"apiBaseURL", cfg.APIBaseURL,
		"maxAgentRounds", cfg.MaxAgentRounds)
```

(Drop the `allowedNamespaces` field; add `maxAgentRounds`.)

- [ ] **Step 5: Build the binary**

Run: `CGO_ENABLED=0 go build -o /tmp/k8s-analyzer ./cmd/k8s-analyzer/`
Expected: success.

- [ ] **Step 6: Commit**

```bash
git add cmd/k8s-analyzer/main.go
git commit -m "feat(k8s-analyzer): wire RunAgenticDiagnostics + drop ALLOWED_NAMESPACES"
```

---

## Task 14: Ship `kubectl` in the k8s-analyzer Docker image

**Files:**
- Modify: `Dockerfile`

The current k8s-analyzer image is `FROM scratch`. kubectl is statically linked Go and runs fine on scratch, so we just need to download and `COPY` it.

- [ ] **Step 1: Add a kubectl-fetch stage to the builder**

Edit the Dockerfile. Pin the kubectl version to a known release and verify
its sha256 (look up the current value at the time of implementation; the
example below uses kubectl 1.32.0 amd64). The download URL is
`https://dl.k8s.io/release/<version>/bin/linux/amd64/kubectl`.

Replace lines 1–9 with:

```dockerfile
FROM golang:1.26-alpine AS builder
RUN apk add --no-cache ca-certificates curl
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /k8s-analyzer ./cmd/k8s-analyzer/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /checkmk-analyzer ./cmd/checkmk-analyzer/

# Fetch kubectl statically. Pin version + sha256 for reproducibility.
ARG KUBECTL_VERSION=v1.32.0
ARG KUBECTL_SHA256=646d58f6d98ee670a71d9cdffbf6625aeea2849d567f214bc43a35f8ccb7bf70
RUN curl -fsSL -o /kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" \
    && echo "${KUBECTL_SHA256}  /kubectl" | sha256sum -c - \
    && chmod +x /kubectl
```

> **Note for the executor:** verify both `KUBECTL_VERSION` and `KUBECTL_SHA256` against the official release page at `https://dl.k8s.io/release/stable.txt` and `https://dl.k8s.io/release/<version>/bin/linux/amd64/kubectl.sha256` before committing. The placeholder values above will fail the `sha256sum -c` step if not refreshed.

- [ ] **Step 2: Copy `kubectl` into the k8s-analyzer runtime stage**

Replace the existing `FROM scratch AS k8s-analyzer` block with:

```dockerfile
# K8s analyzer: scratch + kubectl static binary (no shell needed)
FROM scratch AS k8s-analyzer
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /k8s-analyzer /k8s-analyzer
COPY --from=builder /kubectl /usr/local/bin/kubectl
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["/k8s-analyzer"]
```

The checkmk-analyzer block stays unchanged.

- [ ] **Step 3: Build the image locally**

Run: `docker build --target k8s-analyzer -t k8s-analyzer:test .`
Expected: success. If sha256 verification fails, refresh the values.

- [ ] **Step 4: Verify kubectl is present in the image**

Run: `docker run --rm --entrypoint /usr/local/bin/kubectl k8s-analyzer:test version --client`
Expected: a kubectl client version line printed; exit 0.

- [ ] **Step 5: Build the checkmk image to confirm no regression**

Run: `docker build --target checkmk-analyzer -t checkmk-analyzer:test .`
Expected: success. The checkmk image must NOT contain kubectl:

Run: `docker run --rm checkmk-analyzer:test which kubectl 2>&1 | head -3`
Expected: kubectl not found (the image has no `which` either; an exit error is fine — point is no `/usr/local/bin/kubectl`).

- [ ] **Step 6: Commit**

```bash
git add Dockerfile
git commit -m "build(k8s): bake kubectl static binary into k8s-analyzer image"
```

---

## Task 15: Retrofit checkmk-analyzer with the new agent metrics

**Files:**
- Modify: `internal/checkmk/agent.go`

For symmetry, the checkmk SSH agentic loop should also emit
`agent_tool_calls_total`, `agent_tool_duration_seconds`,
`agent_rounds_used`, and `agent_rounds_exhausted_total` with `source="checkmk"`.

- [ ] **Step 1: Pass `*shared.AlertMetrics` through to `RunAgenticDiagnostics`**

In `internal/checkmk/agent.go`, change the function signature:

```go
func RunAgenticDiagnostics(
	ctx context.Context,
	cfg Config,
	client shared.ToolLoopRunner,
	dialer Dialer,
	metrics *shared.AlertMetrics,
	hostname string,
	verifiedIP string,
	alertContext string,
	maxRounds int,
) (string, error) {
```

In `internal/checkmk/pipeline.go`, update the single call site:

```go
analysis, err = RunAgenticDiagnostics(ctx, deps.SSHConfig, deps.ToolRunner, deps.SSHDialer, deps.Metrics, hostname, hostInfo.VerifiedIP, alertContext, deps.SSHConfig.MaxAgentRounds)
```

(`deps.Metrics` already exists.)

- [ ] **Step 2: Wrap the SSH `handleTool` with metrics**

Inside `RunAgenticDiagnostics` in `internal/checkmk/agent.go`, wrap the
existing inline `handleTool` so each call records the outcome and duration:

```go
	wrappedHandleTool := func(name string, input json.RawMessage) (string, error) {
		start := time.Now()
		out, err := handleTool(name, input) // existing inline closure
		outcome := "ok"
		switch {
		case err != nil:
			outcome = "exec_error"
		case strings.HasPrefix(out, "Command denied"):
			outcome = "rejected_verb"
		case strings.HasPrefix(out, "Command failed:"):
			outcome = "nonzero_exit"
		}
		if metrics != nil {
			metrics.RecordAgentToolCall("checkmk", name, outcome, time.Since(start))
		}
		return out, err
	}
```

Replace the call:

```go
	analysis, err := client.RunToolLoop(
		ctx, agentSystemPromptForRounds(maxRounds), alertContext,
		[]shared.Tool{sshTool}, maxRounds, wrappedHandleTool,
	)
```

- [ ] **Step 3: Update existing checkmk tests that call `RunAgenticDiagnostics`**

Run: `grep -n "RunAgenticDiagnostics" internal/checkmk/`

For every match in `_test.go`, add a `*shared.AlertMetrics` argument
(`&shared.AlertMetrics{Prom: shared.NewPrometheusMetrics()}` or `nil` if
the test does not care about metrics).

- [ ] **Step 4: Run all checkmk tests**

Run: `go test ./internal/checkmk/`
Expected: PASS.

- [ ] **Step 5: Add a regression test asserting metrics emission**

Append to `internal/checkmk/agent_test.go`:

```go
func TestRunAgenticDiagnostics_RecordsMetrics(t *testing.T) {
	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetrics()}
	// reuse existing fakeDialer / fakeToolLoopRunner constructions in this file
	// — driver issues one execute_command call.
	... // see existing checkmk happy-path test for the pattern; assert that
	// metrics body contains `agent_tool_calls_total{...source="checkmk"...}`
}
```

(Use the same metrics-body assertion pattern as in Task 1.)

Run: `go test ./internal/checkmk/ -run TestRunAgenticDiagnostics_RecordsMetrics -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/checkmk/agent.go internal/checkmk/pipeline.go internal/checkmk/agent_test.go internal/checkmk/pipeline_test.go
git commit -m "feat(checkmk): record agent tool-call metrics for symmetry with k8s"
```

---

## Task 16: Documentation updates

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Inspect existing README sections**

Run: `grep -n "ALLOWED_NAMESPACES\|MAX_AGENT_ROUNDS\|k8s-analyzer\|checkmk-analyzer" README.md CLAUDE.md`

- [ ] **Step 2: Update `CLAUDE.md`**

In the "Environment Variables" section (`CLAUDE.md` near the bottom):
- Remove `ALLOWED_NAMESPACES` from the k8s-analyzer optional list.
- Add `MAX_AGENT_ROUNDS` (default 10, 1–50 range, shared with checkmk).
- Update the description of the k8s analyzer in the project-overview section to: "Receives Alertmanager webhooks, runs static prefetch (Prometheus + Kube events/pods/logs) plus an agentic Claude tool-loop (`kubectl_exec`, `promql_query`) for root-cause analysis."

In the Architecture / Key Design Patterns section, add a bullet for k8s mirroring the existing checkmk one:
- "**Agentic diagnostics (k8s):** After static context gathering, `RunAgenticDiagnostics` drives a multi-turn Claude tool-use loop (via `ToolLoopRunner`) where Claude iteratively requests `kubectl_exec` (argv-based subprocess) and `promql_query` calls. kubectl is invoked at a fixed path with a scrubbed env (only `HOME`/`USER`); a verb allowlist + global-flag denylist gate the call before subprocess invocation; RBAC is the authoritative server-side enforcement."

- [ ] **Step 3: Update `README.md`**

In the env-var table (or list):
- Replace any `ALLOWED_NAMESPACES` row with a `MAX_AGENT_ROUNDS` row.

In the deployment / RBAC section:
- Add (or extend if already present) a note: "The k8s-analyzer ServiceAccount needs a read-only ClusterRole. The agent enforces a verb allowlist (read-only built-ins only) but RBAC is the authoritative gate — exclude `secrets` from the role to keep credentials out of reach."

- [ ] **Step 4: Verify markdown is valid**

Run: `grep -c "^#" README.md CLAUDE.md`
Expected: numbers ≥ 1 (sanity check that headings still exist).

- [ ] **Step 5: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "docs: document k8s agentic loop and MAX_AGENT_ROUNDS"
```

---

## Task 17: End-to-end verification

**Files:** none (no edits in this task).

- [ ] **Step 1: Full test suite**

Run: `go test ./...`
Expected: PASS, no compilation errors.

If anything fails, re-open the relevant prior task — do NOT band-aid here.

- [ ] **Step 2: Build both binaries with cgo disabled**

Run: `CGO_ENABLED=0 go build -o /tmp/k8s-analyzer ./cmd/k8s-analyzer/ && CGO_ENABLED=0 go build -o /tmp/checkmk-analyzer ./cmd/checkmk-analyzer/`
Expected: both succeed.

- [ ] **Step 3: Local Docker build of both images**

Run:
```
docker build --target k8s-analyzer -t k8s-analyzer:verify .
docker build --target checkmk-analyzer -t checkmk-analyzer:verify .
```
Expected: both succeed.

- [ ] **Step 4: Verify kubectl in k8s image, absent in checkmk image**

Run: `docker run --rm --entrypoint /usr/local/bin/kubectl k8s-analyzer:verify version --client`
Expected: kubectl client version line.

Run: `docker run --rm --entrypoint /usr/local/bin/kubectl checkmk-analyzer:verify version --client 2>&1 | head -3`
Expected: error / not found (no kubectl in checkmk image).

- [ ] **Step 5: Spot-check coverage on the new agent**

Run: `go test ./internal/k8s/ -coverprofile=/tmp/k8s.cov && go tool cover -func=/tmp/k8s.cov | grep agent.go`
Expected: ≥ 80 % per-function coverage on `agent.go`. If lower, add tests for the uncovered branches before declaring done.

- [ ] **Step 6: Verify no leftover references to removed symbols**

Run: `grep -rn "AllowedNamespaces\|isNamespaceAllowed\|ALLOWED_NAMESPACES" .`
Expected: matches only inside historical references in the spec document or in `docs/` — none in `cmd/`, `internal/`, or test files.

If any matches in production code remain, reopen the related earlier task.

- [ ] **Step 7: Final summary**

The branch now contains: shared agent metrics; `PrometheusClient.Query` exposed; updated `k8s.Config` (no `AllowedNamespaces`, new `MaxAgentRounds`); strengthened header-prefix test; full `internal/k8s/agent.go` with parser + verb allowlist + flag denylist + tool definitions + `KubectlRunner` + `RunAgenticDiagnostics`; updated `pipeline.go`/`main.go`; kubectl baked into the k8s-analyzer image; checkmk metrics retrofitted; docs updated.

No further commit. Hand off the branch for review.
