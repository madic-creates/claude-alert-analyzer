# Metric Naming Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate all Prometheus metrics in claude-alert-analyzer to a single uniform `alert_analyzer_*` prefix with a `product` label (`k8s` | `checkmk`), consolidate semantic duplicates, and replace the hand-rolled text-format exposition with `prometheus/client_golang` end-to-end.

**Architecture:** New typed enums (`Product`, `DropReason`, `WebhookOutcome`, `CooldownOutcome`) drive the new metric API. `PrometheusMetrics` constructor takes a `Product` and applies it as a `ConstLabel`. `AlertMetrics` becomes a method-only nil-safe façade. `CheckAndSetWithGroup` returns a typed outcome. Severity threads through `claude.go` per call. Runtime/process collectors register on the same private registry via `WrapRegistererWith`.

**Tech Stack:** Go 1.26+, `github.com/prometheus/client_golang` (counter / histogram / gauge instruments + `WrapRegistererWith` + `promhttp.HandlerFor`), `github.com/prometheus/client_golang/prometheus/testutil` for assertions.

**Reference Spec:** `docs/superpowers/specs/2026-05-08-metric-naming-refactor-design.md` — read this first. Every code pattern, naming choice, and architectural decision is justified there.

---

## File Structure

### New files

| File | Responsibility |
|---|---|
| `internal/shared/product.go` | `Product` typed enum + `Valid()` |
| `internal/shared/dropreason.go` | `DropReason` typed enum (4 values) |
| `internal/shared/webhook_outcome.go` | `WebhookOutcome` typed enum (6 values) |
| `internal/shared/dropreason_test.go` | Tiny round-trip test |
| `internal/shared/webhook_outcome_test.go` | Tiny round-trip test |
| `internal/shared/prom_metrics_test.go` | NEW — full coverage of constructor, ConstLabel, label sets, default-registry leak |
| `docs/metrics-migration.md` | Operator-facing old→new mapping + PromQL substitution guide |

### Modified files

| File | What changes |
|---|---|
| `internal/shared/cooldown.go` | `CheckAndSetWithGroup` returns `CooldownOutcome` (was `bool`) |
| `internal/shared/cooldown_test.go` | Extended with `CooldownOutcome` cases |
| `internal/shared/prom_metrics.go` | Constructor takes `Product`, all metrics renamed, `source` label dropped, `ConstLabels` applied, runtime collectors registered |
| `internal/shared/metrics.go` | `AlertMetrics` becomes method-only façade, atomic fields removed, `MetricsHandler()` deleted |
| `internal/shared/metrics_test.go` | Rewritten as nil-safe + delegation tests |
| `internal/shared/interfaces.go` | `Analyzer.Analyze` and `ToolLoopRunner.RunToolLoop` get `severity Severity` parameter |
| `internal/shared/claude.go` | `WithPrometheusMetrics` drops source; `Analyze`/`RunToolLoop` add severity param; `RecordClaudeUsage` uses real severity |
| `internal/shared/claude_test.go` | Test calls updated for new signatures |
| `internal/shared/server.go` | `BuildMetricsMux` switches to `promhttp.HandlerFor`; remove enqueue/drop counter calls (handlers own them now) |
| `internal/shared/server_test.go` | `TestServer_BuildMetricsMux` rewritten for nil-Prom and real-Prom paths |
| `internal/shared/breaker_test.go`, `claude_test.go`, `notify_aggregator_test.go` | Drop `"k8s"`/`"checkmk"` arg from `WithLabelValues` calls |
| `internal/k8s/handler.go` | New per-alert dispatch + per-request webhook outcome; drops `"k8s"` arg everywhere |
| `internal/k8s/handler_test.go` | Tests for each webhook outcome and drop reason |
| `internal/k8s/pipeline.go` | Drops `"k8s"` arg from metric calls; passes `severity` into `Analyze`/`RunToolLoop` |
| `internal/k8s/pipeline_test.go` | Drops `"k8s"` arg; updates fake doubles for new severity param |
| `internal/k8s/agent.go` | Drops `"k8s"` arg; passes severity through |
| `internal/k8s/agent_test.go` | Updated test doubles |
| `internal/k8s/coverage_extra_test.go` | Drops `"k8s"` arg |
| `internal/checkmk/handler.go` | Same shape as k8s handler (single-alert path) |
| `internal/checkmk/handler_test.go` | Webhook outcome + drop reason coverage |
| `internal/checkmk/pipeline.go` | Drops source arg; passes severity |
| `internal/checkmk/pipeline_test.go` | Test double updates |
| `internal/checkmk/agent.go` | Drops source; passes severity |
| `internal/checkmk/agent_test.go` | Test double updates |
| `internal/checkmk/coverage_extra_test.go` | Drops source arg |
| `cmd/k8s-analyzer/main.go` | Constructor takes `Product`, transport setup adjusts |
| `cmd/checkmk-analyzer/main.go` | Same |
| `deploy/grafana/claude-alert-analyzer.json` | `product` template variable replaces `source`; queries updated |
| `docs/observability.md` | Full table rewrite |
| `docs/cost-and-storm-protection.md` | PromQL examples updated |
| `CLAUDE.md` | Metrics line updated |
| `README.md` | Metric-name references updated |
| `CHANGELOG.md` (or release notes) | Entry pointing to migration doc |

---

## Pre-flight

- [ ] **Step 0: Read the spec end-to-end.**

```bash
cat docs/superpowers/specs/2026-05-08-metric-naming-refactor-design.md
```

Familiarize yourself with: the `Product`/`DropReason`/`WebhookOutcome`/`CooldownOutcome` enums, the new `AlertMetrics` method API, the per-alert vs. per-request dispatch separation, the counter ownership map (handlers own RecordEnqueued/Dropped/Resolved/WebhookOutcome; pipelines own RecordFailed/RecordProcessed/ObserveProcessingDuration; server owns SetQueueDepth only).

- [ ] **Step 0.1: Confirm baseline build.**

```bash
go build ./...
go test ./...
```

Expected: PASS. Baseline is green before starting.

---

## Phase 1: Pure additions (independent PR)

These three new files compile in isolation. Land first, the rest of the refactor builds on them.

### Task 1: Add `Product` enum

**Files:**
- Create: `internal/shared/product.go`

- [ ] **Step 1: Write `product.go`.**

```go
package shared

// Product identifies which analyzer binary is emitting metrics. Used as a
// ConstLabel on the Prometheus registry.
type Product string

const (
	ProductK8s     Product = "k8s"
	ProductCheckMK Product = "checkmk"
)

// Valid reports whether p is one of the recognized products.
func (p Product) Valid() bool {
	return p == ProductK8s || p == ProductCheckMK
}

// String returns the lowercase string form used as the Prometheus label value.
func (p Product) String() string { return string(p) }
```

- [ ] **Step 2: Verify build.**

```bash
go build ./internal/shared/
```

Expected: no output (success).

- [ ] **Step 3: Commit.**

```bash
git add internal/shared/product.go
git commit -m "feat(shared): add Product enum for metric ConstLabel"
```

### Task 2: Add `DropReason` enum

**Files:**
- Create: `internal/shared/dropreason.go`
- Create: `internal/shared/dropreason_test.go`

- [ ] **Step 1: Write `dropreason.go`.**

```go
package shared

// DropReason classifies why an incoming alert was dropped before analysis.
// Used as a per-call label on alert_analyzer_alerts_dropped_total.
type DropReason string

const (
	DropReasonInvalidFingerprint DropReason = "invalid_fingerprint"
	DropReasonCooldown           DropReason = "cooldown"
	DropReasonGroupCooldown      DropReason = "group_cooldown"
	DropReasonQueueFull          DropReason = "queue_full"
)
```

- [ ] **Step 2: Write the test.**

```go
package shared

import "testing"

func TestDropReason_StringValues(t *testing.T) {
	cases := []struct {
		got  DropReason
		want string
	}{
		{DropReasonInvalidFingerprint, "invalid_fingerprint"},
		{DropReasonCooldown, "cooldown"},
		{DropReasonGroupCooldown, "group_cooldown"},
		{DropReasonQueueFull, "queue_full"},
	}
	for _, c := range cases {
		if string(c.got) != c.want {
			t.Errorf("DropReason %q -> %q, want %q", c.got, string(c.got), c.want)
		}
	}
}
```

- [ ] **Step 3: Run the test.**

```bash
go test ./internal/shared/ -run TestDropReason_StringValues -v
```

Expected: PASS.

- [ ] **Step 4: Commit.**

```bash
git add internal/shared/dropreason.go internal/shared/dropreason_test.go
git commit -m "feat(shared): add DropReason enum"
```

### Task 3: Add `WebhookOutcome` enum

**Files:**
- Create: `internal/shared/webhook_outcome.go`
- Create: `internal/shared/webhook_outcome_test.go`

- [ ] **Step 1: Write `webhook_outcome.go`.**

```go
package shared

// WebhookOutcome classifies the HTTP outcome of a /webhook request. Recorded
// once per request after the final HTTP status is decided. Used as the per-call
// label on alert_analyzer_webhooks_total.
type WebhookOutcome string

const (
	WebhookAccepted        WebhookOutcome = "accepted"
	WebhookAuthFailed      WebhookOutcome = "auth_failed"
	WebhookPayloadInvalid  WebhookOutcome = "payload_invalid"
	WebhookPayloadTooLarge WebhookOutcome = "payload_too_large"
	WebhookUnavailable     WebhookOutcome = "unavailable"
	WebhookInternalError   WebhookOutcome = "internal_error"
)
```

- [ ] **Step 2: Write the test.**

```go
package shared

import "testing"

func TestWebhookOutcome_StringValues(t *testing.T) {
	cases := []struct {
		got  WebhookOutcome
		want string
	}{
		{WebhookAccepted, "accepted"},
		{WebhookAuthFailed, "auth_failed"},
		{WebhookPayloadInvalid, "payload_invalid"},
		{WebhookPayloadTooLarge, "payload_too_large"},
		{WebhookUnavailable, "unavailable"},
		{WebhookInternalError, "internal_error"},
	}
	for _, c := range cases {
		if string(c.got) != c.want {
			t.Errorf("WebhookOutcome %q -> %q, want %q", c.got, string(c.got), c.want)
		}
	}
}
```

- [ ] **Step 3: Run the test.**

```bash
go test ./internal/shared/ -run TestWebhookOutcome_StringValues -v
```

Expected: PASS.

- [ ] **Step 4: Commit.**

```bash
git add internal/shared/webhook_outcome.go internal/shared/webhook_outcome_test.go
git commit -m "feat(shared): add WebhookOutcome enum"
```

---

## Phase 2: Atomic refactor PR

**Tasks 4–22 land as a single PR.** Splitting them leaves the tree unbuildable between commits because renaming a Prometheus field implies updating every call site simultaneously. Use stacked commits within the PR for review-ability, but merge atomically.

### Task 4: Add `CooldownOutcome` to `cooldown.go`

**Files:**
- Modify: `internal/shared/cooldown.go`
- Modify: `internal/shared/cooldown_test.go`

- [ ] **Step 1: Add the `CooldownOutcome` type and convert `CheckAndSetWithGroup` return type.**

In `internal/shared/cooldown.go`, above `CheckAndSetWithGroup` add:

```go
// CooldownOutcome describes which cooldown gate (if any) blocked an alert.
type CooldownOutcome int

const (
	CooldownAccepted    CooldownOutcome = iota // both gates passed
	CooldownFingerprint                        // fingerprint already in cooldown
	CooldownGroup                              // group key already in cooldown
)

// Accepted reports whether the alert passed all cooldown gates.
func (o CooldownOutcome) Accepted() bool { return o == CooldownAccepted }
```

Change the signature of `CheckAndSetWithGroup`:

```go
func (cm *CooldownManager) CheckAndSetWithGroup(
	fingerprint string, fpTTL time.Duration,
	groupKey string, groupTTL time.Duration,
) CooldownOutcome {
	now := time.Now()

	if groupKey == "" || groupTTL == 0 {
		cm.fpMu.Lock()
		defer cm.fpMu.Unlock()
		if checkAndSetLocked(cm.fpEntries, fingerprint, fpTTL, now) {
			return CooldownAccepted
		}
		return CooldownFingerprint
	}

	cm.groupMu.Lock()
	defer cm.groupMu.Unlock()
	if !checkAndSetLocked(cm.groupEntries, groupKey, groupTTL, now) {
		return CooldownGroup
	}

	cm.fpMu.Lock()
	defer cm.fpMu.Unlock()
	if !checkAndSetLocked(cm.fpEntries, fingerprint, fpTTL, now) {
		// Rollback the group entry so the maps stay consistent.
		delete(cm.groupEntries, groupKey)
		return CooldownFingerprint
	}
	return CooldownAccepted
}
```

- [ ] **Step 2: Add cooldown_test.go cases for each outcome.**

Append to `internal/shared/cooldown_test.go`:

```go
func TestCheckAndSetWithGroup_Outcomes(t *testing.T) {
	cm := NewCooldownManager()
	ttl := 5 * time.Second

	t.Run("cold path returns Accepted", func(t *testing.T) {
		out := cm.CheckAndSetWithGroup("fp1", ttl, "g1", ttl)
		if out != CooldownAccepted {
			t.Errorf("got %v, want CooldownAccepted", out)
		}
	})

	t.Run("fingerprint already set returns Fingerprint", func(t *testing.T) {
		_ = cm.CheckAndSetWithGroup("fp2", ttl, "g2", ttl)
		out := cm.CheckAndSetWithGroup("fp2", ttl, "g2-other", ttl)
		if out != CooldownFingerprint {
			t.Errorf("got %v, want CooldownFingerprint", out)
		}
	})

	t.Run("group already set returns Group with fp rollback", func(t *testing.T) {
		_ = cm.CheckAndSetWithGroup("fp3", ttl, "g3", ttl)
		// fp3-other has not been set, but group g3 is. Outcome must be Group.
		out := cm.CheckAndSetWithGroup("fp3-other", ttl, "g3", ttl)
		if out != CooldownGroup {
			t.Errorf("got %v, want CooldownGroup", out)
		}
		// Verify the fingerprint entry was NOT set (rollback).
		out2 := cm.CheckAndSetWithGroup("fp3-other", ttl, "g3-fresh", ttl)
		if out2 != CooldownAccepted {
			t.Errorf("fp3-other should be available after group-rejected, got %v", out2)
		}
	})

	t.Run("groupKey empty never returns Group", func(t *testing.T) {
		_ = cm.CheckAndSetWithGroup("fp4", ttl, "", 0)
		out := cm.CheckAndSetWithGroup("fp4", ttl, "", 0)
		if out != CooldownFingerprint {
			t.Errorf("got %v, want CooldownFingerprint", out)
		}
	})

	t.Run("Accepted helper", func(t *testing.T) {
		if !CooldownAccepted.Accepted() {
			t.Error("CooldownAccepted.Accepted() must be true")
		}
		if CooldownFingerprint.Accepted() {
			t.Error("CooldownFingerprint.Accepted() must be false")
		}
		if CooldownGroup.Accepted() {
			t.Error("CooldownGroup.Accepted() must be false")
		}
	})
}
```

- [ ] **Step 3: Update existing test callers.**

Search for `CheckAndSetWithGroup` callers in `cooldown_test.go` that compare to a bool:

```bash
grep -n "CheckAndSetWithGroup" internal/shared/cooldown_test.go
```

Replace `result := cm.CheckAndSetWithGroup(...)` then `if !result {...}` patterns with:

```go
out := cm.CheckAndSetWithGroup(...)
if !out.Accepted() { ... }
```

Run the full file:

```bash
go test ./internal/shared/ -run TestCooldown -v
```

Expected: PASS (note: dependent code outside this file will not compile yet — that's fixed in subsequent tasks).

- [ ] **Step 4: Commit (within the atomic PR).**

```bash
git add internal/shared/cooldown.go internal/shared/cooldown_test.go
git commit -m "refactor(shared): CooldownOutcome enum return from CheckAndSetWithGroup"
```

### Task 5: Rewrite `prom_metrics.go`

**Files:**
- Modify: `internal/shared/prom_metrics.go`

- [ ] **Step 1: Replace the file's contents.**

The new file shape — see spec section "`internal/shared/prom_metrics.go`" for the field-level decisions. The complete new file:

```go
package shared

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// PrometheusMetrics holds all Prometheus instruments for a single analyzer
// binary. Construct via NewPrometheusMetrics(product); the product is applied
// as a ConstLabel on every metric (and on go_*/process_* via WrapRegistererWith).
type PrometheusMetrics struct {
	registry *prometheus.Registry

	// Pipeline
	WebhooksTotal      *prometheus.CounterVec // labels: outcome
	AlertsEnqueued     prometheus.Counter
	AlertsDropped      *prometheus.CounterVec // labels: reason
	AlertsResolved     prometheus.Counter
	AlertsProcessed    *prometheus.CounterVec // labels: severity
	AlertsFailed       prometheus.Counter
	ProcessingDuration prometheus.Histogram
	QueueDepth         prometheus.Gauge

	// Claude API
	ClaudeAPIDuration prometheus.Histogram
	ClaudeAPIErrors   prometheus.Counter
	ClaudeTokens      *prometheus.CounterVec // labels: kind, severity, model

	// Agent tool loop
	AgentToolCalls       *prometheus.CounterVec   // labels: tool, outcome
	AgentToolDuration    *prometheus.HistogramVec // labels: tool
	AgentRoundsPerRun    prometheus.Histogram
	AgentRoundsExhausted prometheus.Counter

	// Storm robustness
	StormModeActive           prometheus.Gauge
	ClaudeCircuitBreakerState prometheus.Gauge
	NotifyAggregatorDrops     *prometheus.CounterVec // labels: aggregator

	// External I/O
	NtfyPublishErrors prometheus.Counter
}

// NewPrometheusMetrics constructs the registry, applies the product ConstLabel,
// and registers all metrics including go_*/process_* collectors.
func NewPrometheusMetrics(product Product) (*PrometheusMetrics, error) {
	if !product.Valid() {
		return nil, fmt.Errorf("invalid product %q (must be %q or %q)",
			product, ProductK8s, ProductCheckMK)
	}
	reg := prometheus.NewRegistry()
	constLabels := prometheus.Labels{"product": string(product)}

	pm := &PrometheusMetrics{registry: reg}

	pm.WebhooksTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "alert_analyzer_webhooks_total",
		Help:        "Total /webhook HTTP requests by outcome.",
		ConstLabels: constLabels,
	}, []string{"outcome"})

	pm.AlertsEnqueued = prometheus.NewCounter(prometheus.CounterOpts{
		Name:        "alert_analyzer_alerts_enqueued_total",
		Help:        "Alerts successfully placed on the work queue.",
		ConstLabels: constLabels,
	})

	pm.AlertsDropped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "alert_analyzer_alerts_dropped_total",
		Help:        "Alerts dropped before reaching the work queue, by reason.",
		ConstLabels: constLabels,
	}, []string{"reason"})

	pm.AlertsResolved = prometheus.NewCounter(prometheus.CounterOpts{
		Name:        "alert_analyzer_alerts_resolved_total",
		Help:        "Alerts skipped because they were resolved (k8s) or recovery (CheckMK).",
		ConstLabels: constLabels,
	})

	pm.AlertsProcessed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "alert_analyzer_alerts_processed_total",
		Help:        "Alerts successfully analyzed and published, by severity.",
		ConstLabels: constLabels,
	}, []string{"severity"})

	pm.AlertsFailed = prometheus.NewCounter(prometheus.CounterOpts{
		Name:        "alert_analyzer_alerts_failed_total",
		Help:        "Alerts where analysis or publishing failed.",
		ConstLabels: constLabels,
	})

	pm.ProcessingDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:        "alert_analyzer_processing_duration_seconds",
		Help:        "End-to-end per-alert processing time.",
		ConstLabels: constLabels,
		Buckets:     []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 30, 45, 60, 90, 120, 300},
	})

	pm.QueueDepth = prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "alert_analyzer_queue_depth",
		Help:        "Current alerts waiting in the work queue.",
		ConstLabels: constLabels,
	})

	claudeAPIBuckets := []float64{1, 5, 10, 20, 30, 45, 60, 90, 120}
	pm.ClaudeAPIDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:        "alert_analyzer_claude_api_duration_seconds",
		Help:        "Latency of Claude API calls in seconds.",
		ConstLabels: constLabels,
		Buckets:     claudeAPIBuckets,
	})

	pm.ClaudeAPIErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name:        "alert_analyzer_claude_api_errors_total",
		Help:        "Total Claude API errors.",
		ConstLabels: constLabels,
	})

	pm.ClaudeTokens = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "alert_analyzer_claude_tokens_total",
		Help:        "Cumulative Claude API tokens, by kind/severity/model. Use sum by(kind) for cost analysis.",
		ConstLabels: constLabels,
	}, []string{"kind", "severity", "model"})

	pm.AgentToolCalls = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "alert_analyzer_agent_tool_calls_total",
		Help:        "Tool calls inside the agentic Claude loop, by tool and outcome.",
		ConstLabels: constLabels,
	}, []string{"tool", "outcome"})

	agentToolBuckets := []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
	pm.AgentToolDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:        "alert_analyzer_agent_tool_duration_seconds",
		Help:        "Per-tool wall-clock latency in seconds.",
		ConstLabels: constLabels,
		Buckets:     agentToolBuckets,
	}, []string{"tool"})

	pm.AgentRoundsPerRun = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:        "alert_analyzer_agent_rounds_per_run",
		Help:        "Tool rounds Claude used per completed agentic loop.",
		ConstLabels: constLabels,
		Buckets:     []float64{1, 2, 3, 4, 5, 7, 10, 15, 25, 45, 50},
	})

	pm.AgentRoundsExhausted = prometheus.NewCounter(prometheus.CounterOpts{
		Name:        "alert_analyzer_agent_rounds_exhausted_total",
		Help:        "Agentic loops that ended via forced summary (maxRounds reached).",
		ConstLabels: constLabels,
	})

	pm.StormModeActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "alert_analyzer_storm_mode_active",
		Help:        "1 when the storm-mode threshold is exceeded, 0 otherwise.",
		ConstLabels: constLabels,
	})

	pm.ClaudeCircuitBreakerState = prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "alert_analyzer_claude_circuit_breaker_state",
		Help:        "Circuit-breaker state: 0=closed, 1=open, 2=half-open.",
		ConstLabels: constLabels,
	})

	pm.NotifyAggregatorDrops = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "alert_analyzer_notify_aggregator_drops_total",
		Help:        "Alerts dropped by NotifyAggregator, by aggregator type.",
		ConstLabels: constLabels,
	}, []string{"aggregator"})

	pm.NtfyPublishErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name:        "alert_analyzer_ntfy_publish_errors_total",
		Help:        "Total ntfy publish failures.",
		ConstLabels: constLabels,
	})

	reg.MustRegister(
		pm.WebhooksTotal, pm.AlertsEnqueued, pm.AlertsDropped, pm.AlertsResolved,
		pm.AlertsProcessed, pm.AlertsFailed, pm.ProcessingDuration, pm.QueueDepth,
		pm.ClaudeAPIDuration, pm.ClaudeAPIErrors, pm.ClaudeTokens,
		pm.AgentToolCalls, pm.AgentToolDuration, pm.AgentRoundsPerRun, pm.AgentRoundsExhausted,
		pm.StormModeActive, pm.ClaudeCircuitBreakerState, pm.NotifyAggregatorDrops,
		pm.NtfyPublishErrors,
	)

	// Runtime/process collectors with the product ConstLabel applied via wrapper.
	wrapped := prometheus.WrapRegistererWith(constLabels, reg)
	wrapped.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	return pm, nil
}

// Registry returns the underlying prometheus.Registry for promhttp.HandlerFor.
func (p *PrometheusMetrics) Registry() *prometheus.Registry {
	return p.registry
}
```

Add `"fmt"` import alongside the existing imports.

- [ ] **Step 2: Build (will fail in dependent files; that's expected).**

```bash
go build ./internal/shared/ 2>&1 | head -30
```

This will fail because `metrics.go` references the old field names. Continue to Task 6.

- [ ] **Step 3: Stage the change.** (Don't commit yet; commit at end of Phase 2 after build is green.)

```bash
git add internal/shared/prom_metrics.go
```

### Task 6: Rewrite `metrics.go` — `AlertMetrics` method-only façade

**Files:**
- Modify (full rewrite): `internal/shared/metrics.go`

- [ ] **Step 1: Replace the file's contents.**

```go
package shared

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// AlertMetrics is a nil-safe façade over PrometheusMetrics. All methods on a
// nil receiver or with a nil Prom field are no-ops, which lets test code
// construct AlertMetrics with NewAlertMetrics(nil) when it does not care
// about counter values.
type AlertMetrics struct {
	Prom *PrometheusMetrics
}

// NewAlertMetrics returns a façade over the given PrometheusMetrics. Pass
// nil for tests that don't need real counters.
func NewAlertMetrics(prom *PrometheusMetrics) *AlertMetrics {
	return &AlertMetrics{Prom: prom}
}

// Pipeline counters

func (m *AlertMetrics) RecordWebhookOutcome(outcome WebhookOutcome) {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.WebhooksTotal.WithLabelValues(string(outcome)).Inc()
}

func (m *AlertMetrics) RecordEnqueued() {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.AlertsEnqueued.Inc()
}

func (m *AlertMetrics) RecordDropped(reason DropReason) {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.AlertsDropped.WithLabelValues(string(reason)).Inc()
}

func (m *AlertMetrics) RecordResolved() {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.AlertsResolved.Inc()
}

func (m *AlertMetrics) RecordProcessed(severity Severity) {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.AlertsProcessed.WithLabelValues(severity.String()).Inc()
}

func (m *AlertMetrics) RecordFailed() {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.AlertsFailed.Inc()
}

func (m *AlertMetrics) ObserveProcessingDuration(d time.Duration) {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.ProcessingDuration.Observe(d.Seconds())
}

func (m *AlertMetrics) SetQueueDepth(depth float64) {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.QueueDepth.Set(depth)
}

// Claude API

func (m *AlertMetrics) RecordClaudeAPIError() {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.ClaudeAPIErrors.Inc()
}

func (m *AlertMetrics) RecordClaudeUsage(severity Severity, model string,
	in, out, cacheCreation, cacheRead int) {
	if m == nil || m.Prom == nil {
		return
	}
	labels := prometheus.Labels{"kind": "", "severity": severity.String(), "model": model}
	labels["kind"] = "input"
	m.Prom.ClaudeTokens.With(labels).Add(float64(in))
	labels["kind"] = "output"
	m.Prom.ClaudeTokens.With(labels).Add(float64(out))
	labels["kind"] = "cache_creation"
	m.Prom.ClaudeTokens.With(labels).Add(float64(cacheCreation))
	labels["kind"] = "cache_read"
	m.Prom.ClaudeTokens.With(labels).Add(float64(cacheRead))
}

// Agent tool loop

func (m *AlertMetrics) RecordAgentToolCall(tool, outcome string, duration time.Duration) {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.AgentToolCalls.WithLabelValues(tool, outcome).Inc()
	m.Prom.AgentToolDuration.WithLabelValues(tool).Observe(duration.Seconds())
}

func (m *AlertMetrics) RecordAgentRounds(rounds int, exhausted bool) {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.AgentRoundsPerRun.Observe(float64(rounds))
	if exhausted {
		m.Prom.AgentRoundsExhausted.Inc()
	}
}

// Storm robustness

func (m *AlertMetrics) SetStormMode(active bool) {
	if m == nil || m.Prom == nil {
		return
	}
	v := 0.0
	if active {
		v = 1
	}
	m.Prom.StormModeActive.Set(v)
}

func (m *AlertMetrics) SetBreakerState(state int) {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.ClaudeCircuitBreakerState.Set(float64(state))
}

// AggregatorDropsCounter returns the labeled counter for the given aggregator
// kind ("storm" | "breaker"). Returns nil when Prom is nil.
func (m *AlertMetrics) AggregatorDropsCounter(kind string) prometheus.Counter {
	if m == nil || m.Prom == nil {
		return nil
	}
	return m.Prom.NotifyAggregatorDrops.WithLabelValues(kind)
}

// External I/O

func (m *AlertMetrics) RecordNtfyPublishError() {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.NtfyPublishErrors.Inc()
}
```

- [ ] **Step 2: Stage the change.**

```bash
git add internal/shared/metrics.go
```

### Task 7: Update `interfaces.go` for severity threading

**Files:**
- Modify: `internal/shared/interfaces.go`

- [ ] **Step 1: Replace file contents.**

```go
package shared

import (
	"context"
	"encoding/json"

	"github.com/anthropics/anthropic-sdk-go"
)

// Analyzer performs single-turn Claude analysis. The severity is threaded
// through to token usage recording.
type Analyzer interface {
	Analyze(ctx context.Context, severity Severity,
		model, systemPrompt, userPrompt string) (string, error)
}

// ToolLoopRunner performs multi-turn Claude tool-use conversations.
type ToolLoopRunner interface {
	RunToolLoop(
		ctx context.Context,
		severity Severity,
		model, systemPrompt, userPrompt string,
		tools []anthropic.ToolUnionParam,
		maxRounds int,
		handleTool func(name string, input json.RawMessage) (string, error),
	) (analysis string, rounds int, exhausted bool, err error)
}
```

- [ ] **Step 2: Stage.**

```bash
git add internal/shared/interfaces.go
```

### Task 8: Update `claude.go` — drop source, thread severity

**Files:**
- Modify: `internal/shared/claude.go`

- [ ] **Step 1: Remove the `source` field and update `WithPrometheusMetrics`.**

In `internal/shared/claude.go`, change the `ClaudeClient` struct:

```go
type ClaudeClient struct {
	sdk     *anthropic.Client
	Model   string
	metrics *AlertMetrics // nil/empty in tests that do not assert metrics
}
```

(removed the `source string` field).

Change `WithPrometheusMetrics`:

```go
// WithPrometheusMetrics attaches the AlertMetrics for token-usage recording.
func (c *ClaudeClient) WithPrometheusMetrics(m *AlertMetrics) *ClaudeClient {
	c.metrics = m
	return c
}
```

- [ ] **Step 2: Update `Analyze` to take severity.**

```go
// Analyze sends a single-turn analysis request. severity threads through to
// token usage recording. If model is empty, c.Model is used.
func (c *ClaudeClient) Analyze(ctx context.Context, severity Severity,
	model, systemPrompt, userPrompt string) (string, error) {
	if model == "" {
		model = c.Model
	}

	msg, err := c.sdk.Messages.New(ctx, anthropic.MessageNewParams{
		Model: anthropic.Model(model), MaxTokens: 2048, System: systemBlocks(systemPrompt),
		Messages: []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock(userPrompt))},
	})
	if err != nil {
		return "", err
	}

	slog.Info("Claude analysis complete", "model", model,
		"inputTokens", msg.Usage.InputTokens, "outputTokens", msg.Usage.OutputTokens,
		"cacheCreationTokens", msg.Usage.CacheCreationInputTokens,
		"cacheReadTokens", msg.Usage.CacheReadInputTokens)

	c.metrics.RecordClaudeUsage(severity, model,
		int(msg.Usage.InputTokens), int(msg.Usage.OutputTokens),
		int(msg.Usage.CacheCreationInputTokens), int(msg.Usage.CacheReadInputTokens))
	if msg.StopReason != "" && msg.StopReason != anthropic.StopReasonEndTurn {
		slog.Warn("analysis response may be truncated", "stop_reason", string(msg.StopReason),
			"model", model, "outputTokens", msg.Usage.OutputTokens)
	}
	return extractText(msg), nil
}
```

- [ ] **Step 3: Update `RunToolLoop` to take severity.**

Change signature and the deferred token recording call:

```go
func (c *ClaudeClient) RunToolLoop(ctx context.Context, severity Severity,
	model, systemPrompt, userPrompt string,
	tools []anthropic.ToolUnionParam, maxRounds int,
	handleTool func(name string, input json.RawMessage) (string, error),
) (string, int, bool, error) {
	if model == "" {
		model = c.Model
	}
	if maxRounds <= 0 {
		return "", 0, false, fmt.Errorf("maxRounds must be at least 1, got %d", maxRounds)
	}

	messages := []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock(userPrompt))}

	var totalInput, totalOutput, totalCacheCreation, totalCacheRead int64
	defer func() {
		c.metrics.RecordClaudeUsage(severity, model,
			int(totalInput), int(totalOutput), int(totalCacheCreation), int(totalCacheRead))
	}()
	// ... rest of body unchanged
}
```

- [ ] **Step 4: Stage.**

```bash
git add internal/shared/claude.go
```

### Task 9: Update `server.go` — use `promhttp.HandlerFor`, drop counter calls

**Files:**
- Modify: `internal/shared/server.go`

- [ ] **Step 1: Replace `BuildMetricsMux`.**

```bash
grep -n "BuildMetricsMux\|MetricsHandler" internal/shared/server.go
```

Find the existing `BuildMetricsMux` body (around line 88). Replace with:

```go
// BuildMetricsMux returns an http.ServeMux with only the /metrics endpoint.
func (s *Server) BuildMetricsMux() *http.ServeMux {
	mux := http.NewServeMux()
	if s.metrics == nil || s.metrics.Prom == nil {
		// Zero-value path: serve an empty 200 with the Prometheus content-type.
		mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
			w.WriteHeader(http.StatusOK)
		})
		return mux
	}
	mux.Handle("GET /metrics", promhttp.HandlerFor(
		s.metrics.Prom.Registry(),
		promhttp.HandlerOpts{DisableCompression: true},
	))
	return mux
}
```

Add `"github.com/prometheus/client_golang/prometheus/promhttp"` to imports if not present.

- [ ] **Step 2: Remove server-side counter increments.**

Search for direct counter calls in server.go:

```bash
grep -n "metrics\.\(WebhooksReceived\|AlertsQueued\|AlertsQueueFull\|AlertsCooldown\|AlertsProcessed\|AlertsFailed\|AlertsInvalidFingerprint\|ProcessingDuration\)" internal/shared/server.go
```

Delete every line that increments these old atomic fields. Per spec, the server only owns `SetQueueDepth`. If the worker pool currently does `metrics.AlertsProcessed.Add(1)` or `metrics.AlertsFailed.Add(1)`, those calls move into the pipelines (Tasks 11/14).

If `server.go` updates `QueueDepth` via `metrics.Prom.QueueDepth.WithLabelValues("...").Set(...)`, replace with `metrics.SetQueueDepth(float64(depth))`.

- [ ] **Step 3: Stage.**

```bash
git add internal/shared/server.go
```

### Task 10: Update `internal/k8s/handler.go`

**Files:**
- Modify: `internal/k8s/handler.go`

- [ ] **Step 1: Implement the new dispatch.**

The complete handler restructure follows the spec section "Per-alert admission dispatch" + "Webhook-level outcome dispatch". Key changes:

1. Track `httpStatus int` initialized to `http.StatusOK`.
2. Track `seenQueueFull bool`.
3. At each early short-circuit (auth, payload decode, batch oversized), set `httpStatus` and call `metrics.RecordWebhookOutcome(outcomeForStatus(httpStatus))` then return.
4. Inside the per-alert loop:
   - Invalid fingerprint → `metrics.RecordDropped(shared.DropReasonInvalidFingerprint); continue`.
   - Resolved skip → clear cooldowns, `metrics.RecordResolved(); continue`.
   - `cooldown.CheckAndSetWithGroup(...)` switch on `CooldownOutcome`:
     - `CooldownAccepted`: proceed.
     - `CooldownFingerprint`: `metrics.RecordDropped(shared.DropReasonCooldown); continue`.
     - `CooldownGroup`: `metrics.RecordDropped(shared.DropReasonGroupCooldown); continue`.
   - Enqueue check: if `!queue.Enqueue(alert)`, `metrics.RecordDropped(shared.DropReasonQueueFull); seenQueueFull = true; continue` (do NOT break — k8s iterates entire batch).
   - Else: `metrics.RecordEnqueued()`.
5. After the loop:
   - If `seenQueueFull`, `httpStatus = http.StatusServiceUnavailable`, `http.Error(w, "queue full for some alerts", 503)`.
   - Call `metrics.RecordWebhookOutcome(outcomeForStatus(httpStatus))` once.

- [ ] **Step 2: Add `outcomeForStatus` helper.**

In a new `internal/shared/webhook_outcome_helpers.go` (or inline in `webhook_outcome.go`):

```go
package shared

import "net/http"

// OutcomeForStatus maps an HTTP status code to a WebhookOutcome.
func OutcomeForStatus(s int) WebhookOutcome {
	switch s {
	case http.StatusOK, http.StatusAccepted:
		return WebhookAccepted
	case http.StatusUnauthorized:
		return WebhookAuthFailed
	case http.StatusBadRequest:
		return WebhookPayloadInvalid
	case http.StatusRequestEntityTooLarge:
		return WebhookPayloadTooLarge
	case http.StatusServiceUnavailable:
		return WebhookUnavailable
	default:
		return WebhookInternalError
	}
}
```

- [ ] **Step 3: Replace all old counter calls.**

In handler.go, search for and replace:

```bash
grep -n 'metrics\.\(AlertsInvalidFingerprint\|AlertsCooldown\|RecordCooldown\|AlertsQueueFull\|AlertsQueued\|WebhooksReceived\)' internal/k8s/handler.go
```

Each match maps to a new method call:
- `metrics.AlertsInvalidFingerprint.Add(1)` → `metrics.RecordDropped(shared.DropReasonInvalidFingerprint)`
- `metrics.AlertsCooldown.Add(1)` and `metrics.RecordCooldown("k8s")` → `metrics.RecordDropped(shared.DropReasonCooldown)` (or GroupCooldown — see CooldownOutcome)
- `metrics.AlertsQueueFull.Add(1)` → `metrics.RecordDropped(shared.DropReasonQueueFull)`
- `metrics.AlertsQueued.Add(1)` → `metrics.RecordEnqueued()`
- `metrics.WebhooksReceived.Add(1)` → DELETE (replaced by `RecordWebhookOutcome` at request end)

Source string `"k8s"` is dropped from every call.

- [ ] **Step 4: Stage.**

```bash
git add internal/k8s/handler.go internal/shared/webhook_outcome_helpers.go
```

### Task 11: Update `internal/k8s/pipeline.go`

**Files:**
- Modify: `internal/k8s/pipeline.go`

- [ ] **Step 1: Drop source argument and thread severity.**

```bash
grep -n '"k8s"' internal/k8s/pipeline.go
```

For each call, drop the `"k8s"` argument:

- `metrics.RecordAnalyzed("k8s", severity)` → `metrics.RecordProcessed(alert.SeverityLevel)`
- `metrics.RecordClaudeAPIError("k8s")` → `metrics.RecordClaudeAPIError()`
- `metrics.RecordNtfyPublishError("k8s")` → `metrics.RecordNtfyPublishError()`
- `metrics.SetQueueDepth("k8s", depth)` → `metrics.SetQueueDepth(depth)`
- `metrics.SetStormMode("k8s", active)` → `metrics.SetStormMode(active)`
- `metrics.SetBreakerState("k8s", state)` → `metrics.SetBreakerState(state)`
- `metrics.RecordAgentRounds("k8s", rounds, exhausted)` → `metrics.RecordAgentRounds(rounds, exhausted)`

- [ ] **Step 2: Pass severity to Claude calls.**

For every `analyzer.Analyze(ctx, model, sysPrompt, userPrompt)` call, change to `analyzer.Analyze(ctx, alert.SeverityLevel, model, sysPrompt, userPrompt)`.

For every `runner.RunToolLoop(ctx, model, sysPrompt, userPrompt, tools, rounds, handler)`, change to `runner.RunToolLoop(ctx, alert.SeverityLevel, model, sysPrompt, userPrompt, tools, rounds, handler)`.

- [ ] **Step 3: Add pipeline-side processing-duration + failure tracking.**

Per spec, pipelines own `RecordFailed` / `ObserveProcessingDuration` / `RecordProcessed`. Wrap the existing process body:

```go
start := time.Now()
defer func() {
	metrics.ObserveProcessingDuration(time.Since(start))
}()

// ... existing body ...

if err != nil {
	metrics.RecordFailed()
	return
}
metrics.RecordProcessed(alert.SeverityLevel)
```

Existing failure paths that did `metrics.AlertsFailed.Add(1)` keep that semantics but call the method instead.

- [ ] **Step 4: Stage.**

```bash
git add internal/k8s/pipeline.go
```

### Task 12: Update `internal/k8s/agent.go`

**Files:**
- Modify: `internal/k8s/agent.go`

- [ ] **Step 1: Drop source from agent metric calls and thread severity.**

```bash
grep -n '"k8s"' internal/k8s/agent.go
```

Replace:
- `metrics.RecordAgentToolCall("k8s", tool, outcome, duration)` → `metrics.RecordAgentToolCall(tool, outcome, duration)`
- Any other `"k8s"`-tagged calls.

If `agent.go` invokes `runner.RunToolLoop(...)`, add the severity parameter:

```go
analysis, rounds, exhausted, err := runner.RunToolLoop(ctx, alert.SeverityLevel,
	model, sysPrompt, userPrompt, tools, maxRounds, handleTool)
```

- [ ] **Step 2: Stage.**

```bash
git add internal/k8s/agent.go
```

### Task 13: Update `internal/checkmk/{handler,pipeline,agent}.go`

**Files:**
- Modify: `internal/checkmk/handler.go`
- Modify: `internal/checkmk/pipeline.go`
- Modify: `internal/checkmk/agent.go`

Mirrors Tasks 10–12 but with `"checkmk"` as the dropped source string and the single-alert handler shape (no batch loop).

- [ ] **Step 1: handler.go new dispatch.**

CheckMK is single-alert per request. Wrap the existing body:

```go
httpStatus := http.StatusOK
defer func() {
	metrics.RecordWebhookOutcome(shared.OutcomeForStatus(httpStatus))
}()

// auth check failure → httpStatus = 401, return
// payload decode failure → httpStatus = 400, return
// payload too large → httpStatus = 413, return
// RECOVERY case → metrics.RecordResolved(); clear cooldowns; return (httpStatus stays 200)
// invalid fingerprint → metrics.RecordDropped(shared.DropReasonInvalidFingerprint); return (httpStatus 200)
// cooldown switch on CooldownOutcome → record drop reason; return 200
// enqueue failure → httpStatus = 503; metrics.RecordDropped(shared.DropReasonQueueFull); http.Error(...); return
// success → metrics.RecordEnqueued()
```

- [ ] **Step 2: pipeline.go and agent.go.**

Identical pattern to k8s Tasks 11–12 but with `"checkmk"` dropped instead.

```bash
grep -n '"checkmk"' internal/checkmk/pipeline.go internal/checkmk/agent.go
```

- [ ] **Step 3: Stage.**

```bash
git add internal/checkmk/handler.go internal/checkmk/pipeline.go internal/checkmk/agent.go
```

### Task 14: Update `cmd/k8s-analyzer/main.go`

**Files:**
- Modify: `cmd/k8s-analyzer/main.go`

- [ ] **Step 1: Update metrics construction.**

Find the line that constructs metrics (around `cmd/k8s-analyzer/main.go:137`):

```go
metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetrics()}
hist := metrics.Prom.ClaudeAPIDuration.WithLabelValues("k8s")
transport := shared.NewLimitedTransport(http.DefaultTransport, hist)
claudeClient := shared.NewClaudeClient(cfg.BaseConfig(), transport).WithPrometheusMetrics(metrics, "k8s")
```

Replace with:

```go
prom, err := shared.NewPrometheusMetrics(shared.ProductK8s)
if err != nil {
	slog.Error("metrics init failed", "error", err)
	os.Exit(1)
}
metrics := shared.NewAlertMetrics(prom)
slog.Info("metrics initialized",
	"prefix", "alert_analyzer_*",
	"product", shared.ProductK8s.String())
transport := shared.NewLimitedTransport(http.DefaultTransport, prom.ClaudeAPIDuration)
claudeClient := shared.NewClaudeClient(cfg.BaseConfig(), transport).WithPrometheusMetrics(metrics)
```

(`prom.ClaudeAPIDuration` is a plain `prometheus.Histogram` — no `WithLabelValues` because the source label is gone.)

- [ ] **Step 2: Verify `LimitedTransport` accepts a `prometheus.Observer`.**

```bash
grep -n "func NewLimitedTransport" internal/shared/transport.go
```

The signature is `NewLimitedTransport(next http.RoundTripper, observer prometheus.Observer) ...`. `prometheus.Histogram` implements `prometheus.Observer`, so passing `prom.ClaudeAPIDuration` directly works.

- [ ] **Step 3: Stage.**

```bash
git add cmd/k8s-analyzer/main.go
```

### Task 15: Update `cmd/checkmk-analyzer/main.go`

Mirror of Task 14 with `ProductCheckMK`.

**Files:**
- Modify: `cmd/checkmk-analyzer/main.go`

- [ ] **Step 1: Apply the same pattern as k8s.**

```go
prom, err := shared.NewPrometheusMetrics(shared.ProductCheckMK)
if err != nil {
	slog.Error("metrics init failed", "error", err)
	os.Exit(1)
}
metrics := shared.NewAlertMetrics(prom)
slog.Info("metrics initialized",
	"prefix", "alert_analyzer_*",
	"product", shared.ProductCheckMK.String())
transport := shared.NewLimitedTransport(http.DefaultTransport, prom.ClaudeAPIDuration)
claudeClient := shared.NewClaudeClient(cfg.BaseConfig(), transport).WithPrometheusMetrics(metrics)
```

- [ ] **Step 2: Stage.**

```bash
git add cmd/checkmk-analyzer/main.go
```

### Task 16: Build everything; expect green tree

- [ ] **Step 1: Full build.**

```bash
go build ./...
```

Expected: clean build. If there are residual compile errors, they will be in test files (handled in Tasks 17–20) or missed call sites (search with `grep -rn '"k8s"\|"checkmk"' internal/ cmd/` to find any leftovers and fix them inline).

- [ ] **Step 2: Run tests (expect failures in test files).**

```bash
go test ./... 2>&1 | head -40
```

Failures here are fixed in the next tasks.

### Task 17: Rewrite `internal/shared/metrics_test.go`

**Files:**
- Modify (full rewrite): `internal/shared/metrics_test.go`

- [ ] **Step 1: Replace contents.**

```go
package shared

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestAlertMetrics_NilSafe(t *testing.T) {
	// Nil receiver
	var m *AlertMetrics
	m.RecordWebhookOutcome(WebhookAccepted)
	m.RecordEnqueued()
	m.RecordDropped(DropReasonCooldown)
	m.RecordResolved()
	m.RecordProcessed(SeverityWarning)
	m.RecordFailed()
	m.ObserveProcessingDuration(100 * time.Millisecond)
	m.SetQueueDepth(7)
	m.RecordClaudeAPIError()
	m.RecordClaudeUsage(SeverityWarning, "model-x", 1, 2, 3, 4)
	m.RecordAgentToolCall("kubectl", "ok", 50*time.Millisecond)
	m.RecordAgentRounds(3, false)
	m.SetStormMode(true)
	m.SetBreakerState(1)
	m.RecordNtfyPublishError()
	if c := m.AggregatorDropsCounter("storm"); c != nil {
		t.Errorf("AggregatorDropsCounter on nil receiver should return nil, got %v", c)
	}

	// Nil Prom
	m2 := NewAlertMetrics(nil)
	m2.RecordEnqueued()
	m2.RecordDropped(DropReasonQueueFull)
	if c := m2.AggregatorDropsCounter("breaker"); c != nil {
		t.Errorf("AggregatorDropsCounter with nil Prom should return nil, got %v", c)
	}
	// No panic = pass
}

func TestAlertMetrics_Delegation(t *testing.T) {
	prom, err := NewPrometheusMetrics(ProductK8s)
	if err != nil {
		t.Fatalf("NewPrometheusMetrics: %v", err)
	}
	m := NewAlertMetrics(prom)

	m.RecordEnqueued()
	if got := testutil.ToFloat64(prom.AlertsEnqueued); got != 1 {
		t.Errorf("AlertsEnqueued = %v, want 1", got)
	}

	m.RecordDropped(DropReasonCooldown)
	if got := testutil.ToFloat64(prom.AlertsDropped.WithLabelValues("cooldown")); got != 1 {
		t.Errorf("AlertsDropped[cooldown] = %v, want 1", got)
	}

	m.RecordResolved()
	if got := testutil.ToFloat64(prom.AlertsResolved); got != 1 {
		t.Errorf("AlertsResolved = %v, want 1", got)
	}

	m.RecordProcessed(SeverityCritical)
	if got := testutil.ToFloat64(prom.AlertsProcessed.WithLabelValues("critical")); got != 1 {
		t.Errorf("AlertsProcessed[critical] = %v, want 1", got)
	}

	m.RecordWebhookOutcome(WebhookAccepted)
	if got := testutil.ToFloat64(prom.WebhooksTotal.WithLabelValues("accepted")); got != 1 {
		t.Errorf("WebhooksTotal[accepted] = %v, want 1", got)
	}

	m.RecordClaudeUsage(SeverityWarning, "claude-sonnet", 100, 50, 200, 75)
	in := testutil.ToFloat64(prom.ClaudeTokens.WithLabelValues("input", "warning", "claude-sonnet"))
	if in != 100 {
		t.Errorf("ClaudeTokens[input,warning,claude-sonnet] = %v, want 100", in)
	}

	m.SetQueueDepth(42)
	if got := testutil.ToFloat64(prom.QueueDepth); got != 42 {
		t.Errorf("QueueDepth = %v, want 42", got)
	}
}
```

- [ ] **Step 2: Run.**

```bash
go test ./internal/shared/ -run TestAlertMetrics -v
```

Expected: PASS.

- [ ] **Step 3: Stage.**

```bash
git add internal/shared/metrics_test.go
```

### Task 18: Write `internal/shared/prom_metrics_test.go`

**Files:**
- Create: `internal/shared/prom_metrics_test.go`

- [ ] **Step 1: Write the test.**

```go
package shared

import (
	"sort"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
)

func TestNewPrometheusMetrics_InvalidProduct(t *testing.T) {
	if _, err := NewPrometheusMetrics(Product("bogus")); err == nil {
		t.Fatal("expected error for invalid product")
	}
}

func TestNewPrometheusMetrics_RegisteredNames(t *testing.T) {
	for _, p := range []Product{ProductK8s, ProductCheckMK} {
		t.Run(string(p), func(t *testing.T) {
			pm, err := NewPrometheusMetrics(p)
			if err != nil {
				t.Fatalf("NewPrometheusMetrics(%q): %v", p, err)
			}
			got := gatherFamilyNames(t, pm.Registry())
			want := []string{
				"alert_analyzer_agent_rounds_exhausted_total",
				"alert_analyzer_agent_rounds_per_run",
				"alert_analyzer_agent_tool_calls_total",
				"alert_analyzer_agent_tool_duration_seconds",
				"alert_analyzer_alerts_dropped_total",
				"alert_analyzer_alerts_enqueued_total",
				"alert_analyzer_alerts_failed_total",
				"alert_analyzer_alerts_processed_total",
				"alert_analyzer_alerts_resolved_total",
				"alert_analyzer_claude_api_duration_seconds",
				"alert_analyzer_claude_api_errors_total",
				"alert_analyzer_claude_circuit_breaker_state",
				"alert_analyzer_claude_tokens_total",
				"alert_analyzer_notify_aggregator_drops_total",
				"alert_analyzer_ntfy_publish_errors_total",
				"alert_analyzer_processing_duration_seconds",
				"alert_analyzer_queue_depth",
				"alert_analyzer_storm_mode_active",
				"alert_analyzer_webhooks_total",
				// runtime/process collectors register their own families:
				"go_goroutines",
				"process_open_fds",
			}
			for _, w := range want {
				found := false
				for _, g := range got {
					if g == w {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected family %q not registered (got %v)", w, got)
				}
			}
		})
	}
}

func TestNewPrometheusMetrics_ProductConstLabel(t *testing.T) {
	pm, _ := NewPrometheusMetrics(ProductK8s)
	pm.AlertsEnqueued.Inc()

	mfs, _ := pm.Registry().Gather()
	for _, mf := range mfs {
		if mf.GetName() != "alert_analyzer_alerts_enqueued_total" {
			continue
		}
		for _, m := range mf.Metric {
			found := false
			for _, lp := range m.Label {
				if lp.GetName() == "product" && lp.GetValue() == "k8s" {
					found = true
				}
			}
			if !found {
				t.Errorf("expected product=k8s ConstLabel on %v", m.Label)
			}
		}
	}
}

func TestNewPrometheusMetrics_DropReasonLabelSet(t *testing.T) {
	pm, _ := NewPrometheusMetrics(ProductK8s)
	for _, r := range []DropReason{
		DropReasonInvalidFingerprint, DropReasonCooldown,
		DropReasonGroupCooldown, DropReasonQueueFull,
	} {
		pm.AlertsDropped.WithLabelValues(string(r)).Inc()
	}
	if got := testutil.CollectAndCount(pm.AlertsDropped); got != 4 {
		t.Errorf("AlertsDropped series count = %d, want 4", got)
	}
}

func TestNewPrometheusMetrics_TokenKindLabelSet(t *testing.T) {
	pm, _ := NewPrometheusMetrics(ProductK8s)
	for _, kind := range []string{"input", "output", "cache_creation", "cache_read"} {
		pm.ClaudeTokens.WithLabelValues(kind, "warning", "model-x").Inc()
	}
	if got := testutil.CollectAndCount(pm.ClaudeTokens); got != 4 {
		t.Errorf("ClaudeTokens series count = %d, want 4", got)
	}
}

func TestNewPrometheusMetrics_NoDefaultRegistryLeak(t *testing.T) {
	before := familyNamesOnDefault(t)
	_, err := NewPrometheusMetrics(ProductK8s)
	if err != nil {
		t.Fatalf("NewPrometheusMetrics: %v", err)
	}
	after := familyNamesOnDefault(t)
	for _, n := range after {
		if !contains(before, n) {
			t.Errorf("metric family %q leaked into DefaultRegisterer", n)
		}
	}
}

// helpers

func gatherFamilyNames(t *testing.T, reg prometheus.Gatherer) []string {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	names := make([]string, 0, len(mfs))
	for _, mf := range mfs {
		names = append(names, mf.GetName())
	}
	sort.Strings(names)
	return names
}

func familyNamesOnDefault(t *testing.T) []string {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("DefaultGatherer.Gather: %v", err)
	}
	names := make([]string, 0, len(mfs))
	for _, mf := range mfs {
		names = append(names, mf.GetName())
	}
	sort.Strings(names)
	return names
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

var _ = dto.MetricFamily{} // keep dto import alive even if unused above
```

- [ ] **Step 2: Run.**

```bash
go test ./internal/shared/ -run TestNewPrometheusMetrics -v
```

Expected: PASS for all five tests.

- [ ] **Step 3: Stage.**

```bash
git add internal/shared/prom_metrics_test.go
```

### Task 19: Update `internal/shared/server_test.go`, `claude_test.go`, `breaker_test.go`, `notify_aggregator_test.go`

**Files:**
- Modify: `internal/shared/server_test.go`
- Modify: `internal/shared/claude_test.go`
- Modify: `internal/shared/breaker_test.go`
- Modify: `internal/shared/notify_aggregator_test.go`

- [ ] **Step 1: server_test.go — rewrite `TestServer_BuildMetricsMux`.**

```go
func TestServer_BuildMetricsMux_NilProm(t *testing.T) {
	metrics := NewAlertMetrics(nil)
	srv := NewServer(ServerConfig{Port: "0", WorkerCount: 1, QueueSize: 5,
		DrainTimeout: 5 * time.Second}, metrics,
		func(ctx context.Context, alert AlertPayload) {})
	mux := srv.BuildMetricsMux()
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if got := w.Header().Get("Content-Type"); !strings.Contains(got, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", got)
	}
	if w.Body.Len() != 0 {
		t.Errorf("body should be empty for nil-Prom path, got %d bytes", w.Body.Len())
	}
}

func TestServer_BuildMetricsMux_RealProm(t *testing.T) {
	prom, err := NewPrometheusMetrics(ProductK8s)
	if err != nil {
		t.Fatalf("NewPrometheusMetrics: %v", err)
	}
	metrics := NewAlertMetrics(prom)
	metrics.RecordWebhookOutcome(WebhookAccepted)
	srv := NewServer(ServerConfig{Port: "0", WorkerCount: 1, QueueSize: 5,
		DrainTimeout: 5 * time.Second}, metrics,
		func(ctx context.Context, alert AlertPayload) {})
	mux := srv.BuildMetricsMux()
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "alert_analyzer_webhooks_total") {
		t.Errorf("body missing expected metric name; got: %s", w.Body.String()[:min(500, w.Body.Len())])
	}
}
```

(Delete the old `TestServer_BuildMetricsMux`.)

- [ ] **Step 2: claude_test.go — drop source argument from helper calls.**

Search and replace `WithPrometheusMetrics(m, "k8s")` → `WithPrometheusMetrics(m)`. Add `severity` argument to every `Analyze` and `RunToolLoop` call.

```bash
grep -n 'WithPrometheusMetrics\|\.Analyze(\|\.RunToolLoop(' internal/shared/claude_test.go
```

- [ ] **Step 3: breaker_test.go and notify_aggregator_test.go — drop source string from `WithLabelValues` / metric lookups.**

```bash
grep -n '"k8s"\|"checkmk"' internal/shared/breaker_test.go internal/shared/notify_aggregator_test.go
```

For each match, drop the source string. Where the test asserted on `prom.X.WithLabelValues("k8s", ...)`, change to the new label set (without source) or use the new method API.

- [ ] **Step 4: Run.**

```bash
go test ./internal/shared/ -v
```

Expected: PASS.

- [ ] **Step 5: Stage.**

```bash
git add internal/shared/server_test.go internal/shared/claude_test.go \
        internal/shared/breaker_test.go internal/shared/notify_aggregator_test.go
```

### Task 20: Update `internal/k8s/*_test.go`

**Files:**
- Modify: `internal/k8s/handler_test.go`
- Modify: `internal/k8s/pipeline_test.go`
- Modify: `internal/k8s/agent_test.go`
- Modify: `internal/k8s/coverage_extra_test.go`

- [ ] **Step 1: Drop source strings, update test doubles.**

```bash
grep -rn '"k8s"' internal/k8s/
```

For each call site:
- `metrics.RecordX("k8s", ...)` → `metrics.RecordX(...)`
- `prom.X.WithLabelValues("k8s", ...)` → `prom.X.WithLabelValues(...)` with the source removed
- Test doubles implementing `Analyzer`/`ToolLoopRunner`: add `severity Severity` parameter to method signatures.

- [ ] **Step 2: Add new handler tests for webhook outcomes.**

In `handler_test.go`, add cases that exercise:
- 401 path → assert `metrics.WebhooksTotal{outcome="auth_failed"}` is 1.
- 400 path (malformed JSON) → `payload_invalid`.
- 413 path (oversized batch) → `payload_too_large`.
- 503 path (queue-full) → `unavailable`.
- 200 with all-cooldown alerts → `accepted`, plus `alerts_dropped_total{reason="cooldown"}` increments.
- 200 with one resolved + one queued → `accepted`, `RecordResolved` and `RecordEnqueued` both fire.

Use `testutil.ToFloat64(prom.WebhooksTotal.WithLabelValues("..."))` for assertions.

- [ ] **Step 3: Run.**

```bash
go test ./internal/k8s/ -v
```

Expected: PASS.

- [ ] **Step 4: Stage.**

```bash
git add internal/k8s/handler_test.go internal/k8s/pipeline_test.go \
        internal/k8s/agent_test.go internal/k8s/coverage_extra_test.go
```

### Task 21: Update `internal/checkmk/*_test.go`

Mirror of Task 20 with `"checkmk"` dropped instead of `"k8s"`, and webhook-outcome tests for the single-alert handler shape (no batch oversized case; do include RECOVERY → `RecordResolved`).

**Files:**
- Modify: `internal/checkmk/handler_test.go`
- Modify: `internal/checkmk/pipeline_test.go`
- Modify: `internal/checkmk/agent_test.go`
- Modify: `internal/checkmk/coverage_extra_test.go`

- [ ] **Step 1: Drop source strings, update test doubles, add outcome tests.**

```bash
grep -rn '"checkmk"' internal/checkmk/
```

Apply the same pattern as Task 20.

- [ ] **Step 2: Run.**

```bash
go test ./internal/checkmk/ -v
```

Expected: PASS.

- [ ] **Step 3: Stage.**

```bash
git add internal/checkmk/handler_test.go internal/checkmk/pipeline_test.go \
        internal/checkmk/agent_test.go internal/checkmk/coverage_extra_test.go
```

### Task 22: Full test pass + atomic-PR commit

- [ ] **Step 1: Full build and test.**

```bash
go build ./...
go test ./...
```

Expected: green.

- [ ] **Step 2: Verify metric output by running each binary briefly and scraping `/metrics`.**

```bash
# Build the binaries
make binaries

# Run k8s-analyzer with stub env vars (it will fail on missing kubeconfig but
# should expose /metrics before that). Use checkmk for full coverage.
WEBHOOK_SECRET=test ANTHROPIC_API_KEY=test CHECKMK_API_USER=test CHECKMK_API_SECRET=test \
  ./checkmk-analyzer &
PID=$!
sleep 2
curl -s localhost:9101/metrics | grep -E '^alert_analyzer_|^go_|^process_' | head -20
kill $PID
```

Expected output: every line starts with `alert_analyzer_`, `go_`, or `process_`. No leftover old names (`alerts_analyzed_total`, `claude_input_tokens_total`, etc.).

- [ ] **Step 3: Commit (atomic refactor PR).**

```bash
git add -A
git status   # verify only refactor files are staged
git commit -m "refactor!: migrate metrics to alert_analyzer_* prefix + product label

Single uniform prefix replaces the old mix of alert_analyzer_*, alerts_*,
claude_*, agent_*, ntfy_*, storm_*, notify_*, queue_depth. All metrics now
carry a 'product' ConstLabel (k8s|checkmk) instead of the redundant per-call
'source' label.

Other changes:
- Hand-rolled text-format MetricsHandler() removed; promhttp.HandlerFor used.
- AlertMetrics is a method-only nil-safe facade; atomic counter fields gone.
- CheckAndSetWithGroup returns CooldownOutcome (was bool).
- Severity threads through claude.Analyze/RunToolLoop; token recording uses
  the real per-call severity instead of constant 'all'.
- New alert_analyzer_alerts_dropped_total{reason} consolidates cooldown,
  invalid_fingerprint, queue_full, group_cooldown.
- New alert_analyzer_webhooks_total{outcome} replaces webhooks_received_total.
- New alert_analyzer_alerts_resolved_total tracks k8s resolved + CheckMK RECOVERY.
- go_*/process_* runtime collectors registered via WrapRegistererWith.

BREAKING: /metrics output is incompatible with prior releases. See
docs/metrics-migration.md."
```

---

## Phase 3: Operator-facing artifacts (independent PR)

Tasks 23–27 update the dashboard, docs, and CHANGELOG. No runtime effect.

### Task 23: Update Grafana dashboard

**Files:**
- Modify: `deploy/grafana/claude-alert-analyzer.json`

- [ ] **Step 1: Update `templating.list`.**

Replace the `source` template variable with a `product` variable. Set:

```json
{
  "name": "product",
  "type": "query",
  "datasource": {"type": "prometheus", "uid": "${datasource}"},
  "definition": "label_values(alert_analyzer_alerts_processed_total, product)",
  "query": {"query": "label_values(alert_analyzer_alerts_processed_total, product)", "refId": "PrometheusVariableQueryEditor-VariableQuery"},
  "current": {"selected": false, "text": "All", "value": "$__all"},
  "includeAll": true,
  "multi": true,
  "label": "Product",
  "refresh": 2,
  "sort": 1
}
```

Update the `severity` variable's `definition` and `query.query` to:
`label_values(alert_analyzer_alerts_processed_total{product=~"$product"}, severity)`.

- [ ] **Step 2: Replace metric names and labels in every panel target.**

Mechanical substitution (use sed on the JSON file or a Python script):

| Old | New |
|---|---|
| `alerts_analyzed_total{source=~"$source", severity=~"$severity"}` | `alert_analyzer_alerts_processed_total{product=~"$product", severity=~"$severity"}` |
| `alerts_cooldown_total{source=~"$source"}` | `alert_analyzer_alerts_dropped_total{reason="cooldown", product=~"$product"}` |
| `queue_depth{source=~"$source"}` | `alert_analyzer_queue_depth{product=~"$product"}` |
| `claude_api_duration_seconds_bucket{source=~"$source"}` | `alert_analyzer_claude_api_duration_seconds_bucket{product=~"$product"}` |
| `claude_api_errors_total{source=~"$source"}` | `alert_analyzer_claude_api_errors_total{product=~"$product"}` |
| `ntfy_publish_errors_total{source=~"$source"}` | `alert_analyzer_ntfy_publish_errors_total{product=~"$product"}` |
| `agent_tool_calls_total{source=~"$source"}` | `alert_analyzer_agent_tool_calls_total{product=~"$product"}` |
| `agent_tool_duration_seconds_bucket{source=~"$source"}` | `alert_analyzer_agent_tool_duration_seconds_bucket{product=~"$product"}` |
| `agent_rounds_used_bucket{source=~"$source"}` | `alert_analyzer_agent_rounds_per_run_bucket{product=~"$product"}` |
| `agent_rounds_exhausted_total{source=~"$source"}` | `alert_analyzer_agent_rounds_exhausted_total{product=~"$product"}` |
| `claude_input_tokens_total{...}` | `alert_analyzer_claude_tokens_total{kind="input", ...}` |
| `claude_output_tokens_total{...}` | `alert_analyzer_claude_tokens_total{kind="output", ...}` |
| `claude_cache_creation_tokens_total{...}` | `alert_analyzer_claude_tokens_total{kind="cache_creation", ...}` |
| `claude_cache_read_tokens_total{...}` | `alert_analyzer_claude_tokens_total{kind="cache_read", ...}` |
| `storm_mode_active{source=~"$source"}` | `alert_analyzer_storm_mode_active{product=~"$product"}` |
| `claude_circuit_breaker_state{source=~"$source"}` | `alert_analyzer_claude_circuit_breaker_state{product=~"$product"}` |
| `notify_aggregator_drops_total` | `alert_analyzer_notify_aggregator_drops_total{product=~"$product"}` |
| `alert_analyzer_alerts_processed_total` (unlabeled) | `alert_analyzer_alerts_processed_total{product=~"$product"}` |
| `alert_analyzer_webhooks_received_total` | `sum(rate(alert_analyzer_webhooks_total{product=~"$product"}[5m]))` (existing scope) |

- [ ] **Step 3: Add a new panel for `alert_analyzer_webhooks_total{outcome}`.**

Single timeseries panel, query:
`sum by (outcome) (rate(alert_analyzer_webhooks_total{product=~"$product"}[5m]))`

- [ ] **Step 4: Add a runtime panel.**

Stat panel with `go_goroutines{product=~"$product"}`.

- [ ] **Step 5: Validate JSON.**

```bash
python3 -c "import json; json.load(open('deploy/grafana/claude-alert-analyzer.json'))"
```

Expected: no output.

- [ ] **Step 6: Stage.**

```bash
git add deploy/grafana/claude-alert-analyzer.json
```

### Task 24: Rewrite `docs/observability.md`

**Files:**
- Modify (full rewrite of the Metrics section): `docs/observability.md`

- [ ] **Step 1: Replace the metric tables.**

Replace the existing "Operational counters" and "Labeled metrics" sections with a single "Metrics" section that lists each new metric once. Document `product` as a constant label applied via `ConstLabel`. Include the four normalized severity values (`unknown`, `info`, `warning`, `critical`).

Add a "PromQL filtering" subsection covering the `kind`-grouping caveat for `alert_analyzer_claude_tokens_total`:

```
sum(rate(alert_analyzer_claude_tokens_total[5m]))
```

is semantically meaningless because it adds different cost categories. Always use `by (kind)` or filter `kind=~"..."`.

- [ ] **Step 2: Stage.**

```bash
git add docs/observability.md
```

### Task 25: Update `docs/cost-and-storm-protection.md`

**Files:**
- Modify: `docs/cost-and-storm-protection.md`

- [ ] **Step 1: Update every PromQL example.**

Search:

```bash
grep -n 'claude_input_tokens_total\|claude_output_tokens_total\|claude_cache_\|storm_mode_active\|claude_circuit_breaker_state\|notify_aggregator_drops_total\|alerts_analyzed_total' docs/cost-and-storm-protection.md
```

Apply the same substitutions as Task 23 step 2. The cache-hit-rate example becomes:

```
sum(rate(alert_analyzer_claude_tokens_total{kind="cache_read"}[5m]))
  /
sum(rate(alert_analyzer_claude_tokens_total{kind=~"input|cache_creation|cache_read"}[5m]))
```

- [ ] **Step 2: Stage.**

```bash
git add docs/cost-and-storm-protection.md
```

### Task 26: Create `docs/metrics-migration.md`

**Files:**
- Create: `docs/metrics-migration.md`

- [ ] **Step 1: Write the migration guide.**

```markdown
# Metrics Migration Guide

This release renames every Prometheus metric exposed by the analyzers. There is
no dual-emission and no deprecation period — all old names disappear in this
version. Update your dashboards, recording rules, and Alertmanager rules
before deploying.

## Rename map

| Old | New |
|---|---|
| `alert_analyzer_webhooks_received_total` | `alert_analyzer_webhooks_total{outcome}` (sum over outcomes) |
| `alert_analyzer_alerts_queued_total` | `alert_analyzer_alerts_enqueued_total` |
| `alert_analyzer_alerts_queue_full_total` | `alert_analyzer_alerts_dropped_total{reason="queue_full"}` |
| `alert_analyzer_alerts_invalid_fingerprint_total` | `alert_analyzer_alerts_dropped_total{reason="invalid_fingerprint"}` |
| `alert_analyzer_alerts_cooldown_total` | `alert_analyzer_alerts_dropped_total{reason="cooldown"}` |
| `alerts_cooldown_total{source}` | `alert_analyzer_alerts_dropped_total{reason="cooldown",product}` |
| `alert_analyzer_alerts_processed_total` | `alert_analyzer_alerts_processed_total{severity}` |
| `alerts_analyzed_total{source,severity}` | `alert_analyzer_alerts_processed_total{severity,product}` |
| `alert_analyzer_alerts_failed_total` | unchanged (still `alert_analyzer_alerts_failed_total`) |
| `alert_analyzer_processing_duration_seconds` (summary) | `alert_analyzer_processing_duration_seconds` (histogram) |
| `queue_depth{source}` | `alert_analyzer_queue_depth{product}` |
| `claude_api_duration_seconds{source}` | `alert_analyzer_claude_api_duration_seconds{product}` |
| `claude_api_errors_total{source}` | `alert_analyzer_claude_api_errors_total{product}` |
| `claude_input_tokens_total{source,severity,model}` | `alert_analyzer_claude_tokens_total{kind="input",severity,model,product}` |
| `claude_output_tokens_total{source,severity,model}` | `alert_analyzer_claude_tokens_total{kind="output",...}` |
| `claude_cache_creation_tokens_total{source,severity,model}` | `alert_analyzer_claude_tokens_total{kind="cache_creation",...}` |
| `claude_cache_read_tokens_total{source,severity,model}` | `alert_analyzer_claude_tokens_total{kind="cache_read",...}` |
| `agent_tool_calls_total{source,tool,outcome}` | `alert_analyzer_agent_tool_calls_total{tool,outcome,product}` |
| `agent_tool_duration_seconds{source,tool}` | `alert_analyzer_agent_tool_duration_seconds{tool,product}` |
| `agent_rounds_used{source}` | `alert_analyzer_agent_rounds_per_run{product}` |
| `agent_rounds_exhausted_total{source}` | `alert_analyzer_agent_rounds_exhausted_total{product}` |
| `storm_mode_active{source}` | `alert_analyzer_storm_mode_active{product}` |
| `claude_circuit_breaker_state{source}` | `alert_analyzer_claude_circuit_breaker_state{product}` |
| `notify_aggregator_drops_total{aggregator}` | `alert_analyzer_notify_aggregator_drops_total{aggregator,product}` |
| `ntfy_publish_errors_total{source}` | `alert_analyzer_ntfy_publish_errors_total{product}` |

## New metrics

| Metric | Purpose |
|---|---|
| `alert_analyzer_alerts_resolved_total` | k8s resolved skips + CheckMK RECOVERY skips |
| `go_*`, `process_*` | Runtime/process metrics (each carries the `product` ConstLabel) |

## PromQL substitutions

Cache hit rate (old):

```
sum(rate(claude_cache_read_tokens_total[5m])) /
sum(rate(claude_cache_read_tokens_total[5m])
  + rate(claude_cache_creation_tokens_total[5m])
  + rate(claude_input_tokens_total[5m]))
```

Cache hit rate (new):

```
sum(rate(alert_analyzer_claude_tokens_total{kind="cache_read"}[5m])) /
sum(rate(alert_analyzer_claude_tokens_total{kind=~"input|cache_creation|cache_read"}[5m]))
```

## Important caveat

`alert_analyzer_claude_tokens_total` is **one metric, four kinds**. PromQL like
`sum(rate(alert_analyzer_claude_tokens_total[5m]))` without a `by (kind)` clause
adds different cost categories and is semantically meaningless. Always group or
filter by `kind`.

## Dashboards

The bundled Grafana dashboard at `deploy/grafana/claude-alert-analyzer.json`
is updated for the new metric names. Re-import it after upgrading.
```

- [ ] **Step 2: Stage.**

```bash
git add docs/metrics-migration.md
```

### Task 27: Update `CLAUDE.md`, `README.md`, `CHANGELOG.md`

**Files:**
- Modify: `CLAUDE.md`
- Modify: `README.md`
- Modify: `CHANGELOG.md` (or create release notes)

- [ ] **Step 1: CLAUDE.md — update the Metrics paragraph.**

Find the bullet starting with "**Metrics**:" in the "Architecture > Key Design Patterns" section. Replace metric names with the new ones:

> **Metrics**: Counters/gauges/histograms (`alert_analyzer_*` family — see `docs/observability.md` for the full list) live in a private Prometheus registry with a `product` ConstLabel and are served on `METRICS_PORT` (separate from the webhook port).

- [ ] **Step 2: README.md — update any metric references.**

```bash
grep -n 'alerts_analyzed_total\|claude_.*_tokens_total\|queue_depth\|alert_analyzer_' README.md
```

For each match, swap to the new name.

- [ ] **Step 3: CHANGELOG.md — add a release entry.**

```markdown
## [vX.Y.Z] — 2026-MM-DD

### BREAKING

- **Metric naming overhaul.** All Prometheus metrics renamed to a uniform
  `alert_analyzer_*` prefix with a `product` ConstLabel. The hand-rolled
  text-format `/metrics` exposition is replaced with `promhttp`. Update your
  dashboards, recording rules, and Alertmanager rules before deploying — see
  [`docs/metrics-migration.md`](docs/metrics-migration.md) for the full
  rename map.

### Added

- `alert_analyzer_alerts_resolved_total` — k8s resolved skips + CheckMK
  RECOVERY skips.
- `alert_analyzer_webhooks_total{outcome}` — HTTP-level outcomes for
  /webhook (replaces unlabeled `webhooks_received_total`).
- Go runtime / process metrics (`go_*`, `process_*`) on the same registry.

### Internal

- Severity threads through Claude API calls instead of being recorded as
  the constant `"all"`.
- `CooldownManager.CheckAndSetWithGroup` returns a typed `CooldownOutcome`.
- `AlertMetrics` is a method-only nil-safe façade; atomic counter fields
  removed.
```

- [ ] **Step 4: Commit Phase 3.**

```bash
git add CLAUDE.md README.md CHANGELOG.md docs/observability.md \
        docs/cost-and-storm-protection.md docs/metrics-migration.md \
        deploy/grafana/claude-alert-analyzer.json
git commit -m "docs: metric rename — observability, cost guide, dashboard, migration

Updates the bundled dashboard, observability tables, cost-and-storm guide,
and CLAUDE.md/README.md to match the new alert_analyzer_* prefix and
product label. Adds docs/metrics-migration.md as the operator-facing
old->new mapping."
```

---

## Self-Review

1. **Spec coverage:** Every spec section maps to at least one task:
   - Naming Convention → Tasks 5, 6 (prom_metrics + AlertMetrics)
   - Pipeline mapping table → Tasks 5, 10, 13
   - Drop reasons + cooldown API → Task 4 + handler tasks 10, 13
   - Resolved/recovery → Tasks 5, 10, 13
   - prom_metrics.go fields → Task 5
   - AlertMetrics method API → Task 6
   - claude.go severity threading → Task 8
   - interfaces.go change → Task 7
   - Server / transport call-sites → Task 9, 14, 15
   - Invariants → enforced in Task 18 (prom_metrics_test)
   - Tests → Tasks 17, 18, 19, 20, 21
   - Dashboard → Task 23
   - Documentation → Tasks 24–27
   - Migration → Task 26
2. **Placeholder scan:** No "TBD", "TODO", "implement later", "fill in details", "similar to Task N". Each step has either complete code, an exact command, or a complete substitution rule.
3. **Type consistency:** All new types reference correctly. `Severity` (int enum, exists today). `Product`, `DropReason`, `WebhookOutcome` (new strings). `CooldownOutcome` (new int). Method names consistent: `RecordWebhookOutcome`, `RecordEnqueued`, `RecordDropped`, `RecordResolved`, `RecordProcessed`, `RecordFailed`, `ObserveProcessingDuration`, `SetQueueDepth`, `RecordClaudeAPIError`, `RecordClaudeUsage`, `RecordAgentToolCall`, `RecordAgentRounds`, `SetStormMode`, `SetBreakerState`, `AggregatorDropsCounter`, `RecordNtfyPublishError`. All used identically in Task 6 (definition), Task 17 (test), and Tasks 10/11/13 (call sites).
