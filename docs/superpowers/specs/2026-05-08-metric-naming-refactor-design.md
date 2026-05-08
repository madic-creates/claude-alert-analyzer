# Metric Naming Refactor — Design Spec

**Date:** 2026-05-08
**Status:** Approved (revised after three rounds of Codex adversarial review)

## Problem

The two analyzers expose Prometheus metrics with two parallel naming conventions:

- `alert_analyzer_*` — unlabeled operational counters in
  `internal/shared/metrics.go`. Implementation: `AlertMetrics` struct with
  atomic int64 fields and a hand-rolled text-format `MetricsHandler()`.
- `alerts_*`, `claude_*`, `agent_*`, `ntfy_*`, `storm_*`, `notify_*`,
  `queue_depth` — labeled metrics in `internal/shared/prom_metrics.go` using
  the `prometheus/client_golang` library, registered on a private
  `prometheus.Registry`. Every metric carries a `source` label (`k8s` or
  `checkmk`) that is constant per binary.

Three concrete problems:

1. **No unified prefix.** Operators with multiple services in one Prometheus
   risk name collisions on generic names like `queue_depth` or
   `agent_tool_calls_total`.
2. **Duplicates.** The same logical event is counted twice:
   - `alert_analyzer_alerts_cooldown_total` (unlabeled) and
     `alerts_cooldown_total{source}` (labeled)
   - `alert_analyzer_alerts_processed_total` (unlabeled) and
     `alerts_analyzed_total{source,severity}` (labeled)
3. **Awkward `source` label.** Each binary is a separate process, so `source`
   is constant per scrape target. The `job` label from Prometheus is not a
   reliable substitute (federation, single-LB scrape jobs, recording rules
   can all strip or override it). The right fix is to keep an explicit
   `product` label as a `ConstLabel`, not to drop the dimension entirely.

Additionally, `metrics.go` reimplements counter / summary semantics manually
(atomic int64 counters, hand-rolled text-format response writer). The
`prometheus/client_golang` library covers this without the boilerplate — but
the `AlertMetrics` struct itself is the nil-safe façade used across
`server.go`, `claude.go`, and a large test surface, so the struct is kept
and only its internals change.

## Goals

- Single shared prefix `alert_analyzer_*` for every application metric.
- Replace the `source` label with an explicit `product` label (`k8s` |
  `checkmk`) applied as a `ConstLabel` at registry construction.
- Consolidate semantically duplicated counters.
- Replace `metrics.go`'s hand-rolled text-format serialization (the
  `MetricsHandler()` function and its atomic counter backing fields) with
  proper Prometheus instruments. Keep the `AlertMetrics` struct as a
  method-only nil-safe façade.
- Add Go runtime / process metrics (`go_*`, `process_*`) back into the
  registry — basic SRE hygiene the current registry intentionally excludes.
- Add a startup log line that prints the registered metric prefix and
  product, so operators upgrading without reading release notes see the
  change immediately.
- Update the Grafana dashboard to use `product` as a label-based template
  variable.
- Update all documentation that references metric names.

## Non-Goals

- Backwards compatibility / dual-emission of old names. Single breaking
  release with a clear migration document.
- Adding application metrics beyond runtime/process and webhook outcomes —
  saturation gauges, queue-age histograms, p999 are deferred to a follow-up.
- Touching the SDK transport / `LimitedTransport` — its internal histogram
  is observation-only.

## Naming Convention

- All application metrics share the prefix `alert_analyzer_`.
- The product (`k8s` or `checkmk`) lives in a `product` label.
- Subsequent name segments describe the subsystem and the measured quantity.
- Suffix conventions:
  - `_total` for monotonic counters
  - `_seconds` for time measurements (histograms)
  - No suffix for gauges
- Lowercase, underscores between words, no acronyms beyond `api`.
- The standard `go_*` and `process_*` collectors keep their canonical names
  (no `alert_analyzer_` prefix); they receive the `product` `ConstLabel` via
  `WrapRegistererWith`.

## Full Metric Mapping

Every metric below carries a `product` label (`k8s` or `checkmk`) applied as
a `ConstLabel`. Per-call labels are listed below.

### Pipeline

| Old | New | Type | Per-call labels |
|---|---|---|---|
| `alert_analyzer_webhooks_received_total` | `alert_analyzer_webhooks_total` | counter | `outcome` |
| `alert_analyzer_alerts_queued_total` | `alert_analyzer_alerts_enqueued_total` | counter | — |
| `alert_analyzer_alerts_queue_full_total` | `alert_analyzer_alerts_dropped_total` | counter | `reason="queue_full"` |
| `alert_analyzer_alerts_invalid_fingerprint_total` | `alert_analyzer_alerts_dropped_total` | counter | `reason="invalid_fingerprint"` |
| `alert_analyzer_alerts_cooldown_total` (unlabeled) | `alert_analyzer_alerts_dropped_total` | counter | `reason="cooldown"` |
| `alerts_cooldown_total{source}` (labeled) | (merged into above) | — | — |
| group-cooldown drops | `alert_analyzer_alerts_dropped_total` | counter | `reason="group_cooldown"` |
| `alert_analyzer_alerts_processed_total` (unlabeled) | `alert_analyzer_alerts_processed_total` | counter | `severity` |
| `alerts_analyzed_total{source,severity}` | (merged into above) | — | — |
| `alert_analyzer_alerts_failed_total` | `alert_analyzer_alerts_failed_total` | counter | — |
| `alert_analyzer_processing_duration_seconds` (summary) | `alert_analyzer_processing_duration_seconds` | **histogram** | — |
| `queue_depth{source}` | `alert_analyzer_queue_depth` | gauge | — |

`alert_analyzer_webhooks_total` replaces the unlabeled `webhooks_received_total`
with an `outcome` label that mirrors the HTTP response. **The label is the
HTTP-level outcome of the request, recorded exactly once per request after
the final HTTP status is decided.** Per-alert events (drops, enqueues,
resolved skips) are tracked by separate metrics. Closed enum:

| HTTP path | `outcome` label |
|---|---|
| Successful response (200/202) | `accepted` |
| Bearer token check fails (401) | `auth_failed` |
| JSON decode fails / shape invalid (400) / batch oversized (413) | `payload_invalid` / `payload_too_large` |
| Queue full / shutdown (503) | `unavailable` |
| Panic-recovered or unclassified server error (500) | `internal_error` |

Queue-full is `unavailable` because the handler returns 503. This matches
operator intuition: `outcome="accepted"` corresponds to a 2xx response.

**Batched k8s handler:** The Alertmanager webhook delivers a batch of alerts
in a single request. `RecordDropped`/`RecordEnqueued`/`RecordProcessed` /
`RecordResolved` (see below) fire **per alert in the batch**.
`RecordWebhookOutcome` fires **once at the end of the request handler**.
**The k8s handler iterates the entire batch even after a queue-full**, so
later alerts in the same batch still emit their per-alert metrics
(`RecordResolved`, `RecordDropped`, `RecordEnqueued`) and still clear
cooldown entries on resolved skips. After the loop completes, if any alert
hit queue-full the handler returns 503; otherwise 200. The webhook outcome
is therefore `unavailable` (503) if at least one alert in the batch was
queue-full, `accepted` (200) otherwise. Early short-circuit outcomes
(401/400/413/500) skip the loop entirely and emit their outcome directly.

**CheckMK handler:** Single alert per request. `RecordWebhookOutcome` is
called once after the final HTTP status; `RecordDropped`/`RecordEnqueued` /
`RecordResolved` once for the alert.

### Resolved / recovery skips (NEW metric)

K8s skips `resolved` alerts (when `SKIP_RESOLVED=true`) and CheckMK skips
`RECOVERY` notifications. These are not drops (no error condition) and not
processings (no Claude analysis). They are tracked by a separate counter:

| New | Type | Per-call labels |
|---|---|---|
| `alert_analyzer_alerts_resolved_total` | counter | — |

Each handler increments via `metrics.RecordResolved()` when it skips a
resolved/recovery alert and clears the corresponding cooldown entries.

Histogram buckets for `processing_duration_seconds`:
`[0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 30, 45, 60, 90, 120, 300]`. Low-end
buckets (0.1, 0.25) cover the fast paths (breaker-open short-circuit,
validation-failed, cache-hit static analyses). Mid/high buckets keep p95/p99
quantile estimation smooth across the agentic-loop range.

The `reason` label values for `alerts_dropped_total` are a closed enum:
`queue_full`, `invalid_fingerprint`, `cooldown`, `group_cooldown`. There is
**no precedence helper or boolean state**. Each admission step is sequential:
fingerprint validation → cooldown check → enqueue. The first failing step
emits its reason directly and returns. See "Drop reasons + cooldown API
change" below.

### Claude API & Tokens

| Old | New | Type | Per-call labels |
|---|---|---|---|
| `claude_api_duration_seconds{source}` | `alert_analyzer_claude_api_duration_seconds` | histogram | — |
| `claude_api_errors_total{source}` | `alert_analyzer_claude_api_errors_total` | counter | — |
| 4× `claude_*_tokens_total{source,severity,model}` | `alert_analyzer_claude_tokens_total` | counter | `kind`, `severity`, `model` |

`kind` is a closed enum: `input`, `output`, `cache_creation`, `cache_read`.

**PromQL caveat (must be documented in operator guide):**
`sum(rate(alert_analyzer_claude_tokens_total[5m]))` (without `by (kind)`) is
semantically meaningless because it adds different cost categories. Every
dashboard panel and recording rule that uses this metric MUST filter or
group by `kind`.

### Agent Tool Loop

| Old | New | Type | Per-call labels |
|---|---|---|---|
| `agent_tool_calls_total{source,tool,outcome}` | `alert_analyzer_agent_tool_calls_total` | counter | `tool`, `outcome` |
| `agent_tool_duration_seconds{source,tool}` | `alert_analyzer_agent_tool_duration_seconds` | histogram | `tool` |
| `agent_rounds_used{source}` | `alert_analyzer_agent_rounds_per_run` | histogram | — |
| `agent_rounds_exhausted_total{source}` | `alert_analyzer_agent_rounds_exhausted_total` | counter | — |

Renamed `agent_rounds_used` → `agent_rounds_per_run` (the original `_used`
suffix is non-standard).

Histogram buckets for `agent_rounds_per_run`:
`[1, 2, 3, 4, 5, 7, 10, 15, 25, 45, 50]`. The `45` bucket sits close to the
policy cap (50) so behavior just before exhaustion is observable.

### Storm Robustness

| Old | New | Type | Per-call labels |
|---|---|---|---|
| `storm_mode_active{source}` | `alert_analyzer_storm_mode_active` | gauge | — |
| `claude_circuit_breaker_state{source}` | `alert_analyzer_claude_circuit_breaker_state` | gauge | — |
| `notify_aggregator_drops_total{aggregator}` | `alert_analyzer_notify_aggregator_drops_total` | counter | `aggregator` |

### External I/O

| Old | New | Type | Per-call labels |
|---|---|---|---|
| `ntfy_publish_errors_total{source}` | `alert_analyzer_ntfy_publish_errors_total` | counter | — |

### Runtime / process (NEW)

The current registry deliberately excludes Go runtime and process collectors.
We re-add them. They keep their canonical names (no `alert_analyzer_` prefix)
and receive the `product` `ConstLabel` via `WrapRegistererWith`.

- `go_*` (heap stats, goroutines, GC) via `collectors.NewGoCollector()`
- `process_*` (CPU, memory, FDs) via `collectors.NewProcessCollector(...)`

## Code Structure Changes

### `internal/shared/product.go` (NEW)

```go
package shared

type Product string

const (
    ProductK8s     Product = "k8s"
    ProductCheckMK Product = "checkmk"
)

func (p Product) Valid() bool {
    return p == ProductK8s || p == ProductCheckMK
}

func (p Product) String() string { return string(p) }
```

### `internal/shared/dropreason.go` (NEW)

Pure enum — no helper functions, no precedence table.

```go
package shared

type DropReason string

const (
    DropReasonInvalidFingerprint DropReason = "invalid_fingerprint"
    DropReasonCooldown           DropReason = "cooldown"
    DropReasonGroupCooldown      DropReason = "group_cooldown"
    DropReasonQueueFull          DropReason = "queue_full"
)
```

### `internal/shared/webhook_outcome.go` (NEW)

```go
package shared

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

### `internal/shared/cooldown.go` API change

`CheckAndSetWithGroup` returns a typed outcome instead of `bool`:

```go
type CooldownOutcome int

const (
    CooldownAccepted CooldownOutcome = iota
    CooldownFingerprint
    CooldownGroup
)

func (o CooldownOutcome) Accepted() bool { return o == CooldownAccepted }

// Returns CooldownAccepted on success, CooldownFingerprint or CooldownGroup
// on rejection. When groupKey == "" or groupTTL == 0 the function reduces to
// a fingerprint-only check; in that mode the only possible non-Accepted
// return is CooldownFingerprint.
func (cm *CooldownManager) CheckAndSetWithGroup(
    fingerprint string, fpTTL time.Duration,
    groupKey string, groupTTL time.Duration,
) CooldownOutcome
```

The atomic + rollback semantics are preserved unchanged: lock-discipline
(`groupMu` → `fpMu`) the same, both mutexes still held over the entire
decision. Only the return value carries more information.

Callers that don't care about the distinction can use `outcome.Accepted()`.

### Per-alert admission dispatch

The per-alert pipeline is a sequence of gates. The first failing gate emits
its drop reason via the `AlertMetrics` method and skips to the next alert
(k8s batch) or returns (CheckMK). No precedence rules. **The webhook-level
outcome is recorded separately, after the request loop completes.**

```go
// per-alert loop body (k8s) or single-alert path (CheckMK)

if !validFingerprint(alert) {
    metrics.RecordDropped(shared.DropReasonInvalidFingerprint)
    continue // k8s; return for CheckMK
}

if isResolvedOrRecovery(alert) {
    cooldown.Clear(fp); cooldown.ClearGroup(groupKey)
    metrics.RecordResolved()
    continue
}

switch outcome := cooldown.CheckAndSetWithGroup(fp, fpTTL, group, groupTTL); outcome {
case shared.CooldownAccepted:
    // proceed
case shared.CooldownFingerprint:
    metrics.RecordDropped(shared.DropReasonCooldown); continue
case shared.CooldownGroup:
    metrics.RecordDropped(shared.DropReasonGroupCooldown); continue
}

if !queue.Enqueue(alert) {
    metrics.RecordDropped(shared.DropReasonQueueFull)
    httpStatus = http.StatusServiceUnavailable
    // k8s: continue iterating the batch (do NOT break). CheckMK: return
    // immediately because there is only one alert per request.
    continue // k8s; return for CheckMK
}

metrics.RecordEnqueued()
```

### Webhook-level outcome dispatch

Recorded once per request after the loop completes:

```go
// k8s handler, after the per-alert loop
defer func() {
    metrics.RecordWebhookOutcome(outcomeForStatus(httpStatus))
}()
```

```go
func outcomeForStatus(s int) shared.WebhookOutcome {
    switch {
    case s == http.StatusOK || s == http.StatusAccepted:
        return shared.WebhookAccepted
    case s == http.StatusUnauthorized:
        return shared.WebhookAuthFailed
    case s == http.StatusBadRequest:
        return shared.WebhookPayloadInvalid
    case s == http.StatusRequestEntityTooLarge:
        return shared.WebhookPayloadTooLarge
    case s == http.StatusServiceUnavailable:
        return shared.WebhookUnavailable
    default:
        return shared.WebhookInternalError
    }
}
```

Auth-failure and payload-decode-failure paths short-circuit before the loop,
record the appropriate `RecordWebhookOutcome(...)` directly, and return.

### `internal/shared/prom_metrics.go`

- Constructor signature:
  `NewPrometheusMetrics(product Product) (*PrometheusMetrics, error)`.
  Returns an error on `!product.Valid()`. Both binaries must check the
  error and exit non-zero on failure.
- Every counter / gauge / histogram is created with
  `ConstLabels: prometheus.Labels{"product": string(product)}`.
- Per-call labels lose the `source` argument across the board.
- All Prometheus interface types are used directly (not as pointers):
  `prometheus.Counter`, `prometheus.Histogram`, `prometheus.Gauge`,
  `*prometheus.CounterVec`, `*prometheus.HistogramVec`, `*prometheus.GaugeVec`.
- Field renames (existing → new):
  - `AlertsAnalyzed` (CounterVec, `[]string{"source","severity"}`) →
    `AlertsProcessed` (CounterVec, `[]string{"severity"}`).
  - `AlertsCooldown` (CounterVec, `[]string{"source"}`) → folded into
    `AlertsDropped` (CounterVec, `[]string{"reason"}`).
  - 4 token CounterVecs → single `ClaudeTokens *prometheus.CounterVec` with
    `[]string{"kind","severity","model"}`.
  - `AgentRoundsUsed` → `AgentRoundsPerRun`.
- New fields (replacing the atomic int64 counters in `AlertMetrics`):
  - `WebhooksTotal *prometheus.CounterVec` with `[]string{"outcome"}`.
  - `AlertsEnqueued prometheus.Counter` (no labels).
  - `AlertsFailed prometheus.Counter` (no labels).
  - `AlertsResolved prometheus.Counter` (no labels) — k8s `resolved` skips
    and CheckMK `RECOVERY` skips.
  - `ProcessingDuration prometheus.Histogram` (no labels).
- Registry construction uses `prometheus.WrapRegistererWith` to attach the
  `product` `ConstLabel` to the `go_*` and `process_*` collectors registered
  on the same private registry.

### `internal/shared/metrics.go` — `AlertMetrics` rewrite

The struct is kept (still used as a typed value across `server.go`,
`claude.go`, and tests) but its internals change:

- Atomic int64 counter fields are **removed**. Direct access via `.Add()`
  and `.Load()` no longer compiles (breaking change inside `internal/shared`,
  contained to that package).
- `MetricsHandler()` is **removed**. Its callers (`server.go`,
  `metrics_test.go`) switch to `promhttp.HandlerFor(prom.Registry(), ...)`.
- Existing helper methods are reshaped to drop the `source` argument and
  align with the new typed enums.

#### New `AlertMetrics` shape

```go
type AlertMetrics struct {
    Prom *PrometheusMetrics  // nil → all methods become no-ops
}

func NewAlertMetrics(prom *PrometheusMetrics) *AlertMetrics {
    return &AlertMetrics{Prom: prom}
}

// All methods are nil-safe at both levels (nil receiver, nil Prom).

// Pipeline
func (m *AlertMetrics) RecordWebhookOutcome(outcome WebhookOutcome)
func (m *AlertMetrics) RecordEnqueued()
func (m *AlertMetrics) RecordDropped(reason DropReason)
func (m *AlertMetrics) RecordResolved()
func (m *AlertMetrics) RecordProcessed(severity Severity)
func (m *AlertMetrics) RecordFailed()
func (m *AlertMetrics) ObserveProcessingDuration(d time.Duration)
func (m *AlertMetrics) SetQueueDepth(depth float64)

// Claude API
func (m *AlertMetrics) RecordClaudeAPIError()
func (m *AlertMetrics) RecordClaudeUsage(severity Severity, model string,
    in, out, cacheCreation, cacheRead int)

// Agent tool loop
func (m *AlertMetrics) RecordAgentToolCall(tool, outcome string, duration time.Duration)
func (m *AlertMetrics) RecordAgentRounds(rounds int, exhausted bool)

// Storm robustness
func (m *AlertMetrics) SetStormMode(active bool)
func (m *AlertMetrics) SetBreakerState(state int)
func (m *AlertMetrics) AggregatorDropsCounter(kind string) prometheus.Counter

// External I/O
func (m *AlertMetrics) RecordNtfyPublishError()
```

Every method begins with `if m == nil || m.Prom == nil { return }`.

#### Test-pattern migration

| Today | After |
|---|---|
| `m := new(AlertMetrics)` then `m.WebhooksReceived.Add(5)` | `m := NewAlertMetrics(nil)` (no-op) or `m := NewAlertMetrics(prom)` for assertions |
| `m.AlertsProcessed.Load()` for assertions | `promtestutil.ToFloat64(prom.AlertsProcessed.WithLabelValues("warning"))` |
| `metrics.MetricsHandler()` in tests | `promhttp.HandlerFor(prom.Registry(), promhttp.HandlerOpts{})` |
| `BuildMetricsMux` zero-Prom test (server_test.go:95) | Construct test with `AlertMetrics{Prom: nil}` and assert handler returns 200 with empty exposition |

When `Prom == nil`, `BuildMetricsMux` produces a handler that returns
HTTP 200 with `Content-Type: text/plain; version=0.0.4` and an empty body.
This matches the existing zero-value behavior the tests rely on.

### `internal/shared/claude.go` API change

Today `ClaudeClient` stores `source` and `Analyze`/`RunToolLoop` defer-record
token usage with severity hardcoded to `"all"`. After:

- **Drop the `source` field.** `WithPrometheusMetrics(m *AlertMetrics)` no
  longer takes a source argument.
- **Severity is passed as a parameter** to `Analyze` and `RunToolLoop`. It
  is not stored on `ClaudeClient` (which is shared across workers — adding
  mutable state would race).

```go
// Before
func (c *ClaudeClient) WithPrometheusMetrics(m *AlertMetrics, source string) *ClaudeClient
func (c *ClaudeClient) Analyze(ctx context.Context, model, sys, user string) (string, error)
func (c *ClaudeClient) RunToolLoop(ctx context.Context, model, sys, user string,
    tools []anthropic.ToolUnionParam, maxRounds int,
    handleTool func(name string, input json.RawMessage) (string, error),
) (string, int, bool, error)

// After
func (c *ClaudeClient) WithPrometheusMetrics(m *AlertMetrics) *ClaudeClient
func (c *ClaudeClient) Analyze(ctx context.Context, severity Severity,
    model, sys, user string) (string, error)
func (c *ClaudeClient) RunToolLoop(ctx context.Context, severity Severity,
    model, sys, user string, tools []anthropic.ToolUnionParam, maxRounds int,
    handleTool func(name string, input json.RawMessage) (string, error),
) (string, int, bool, error)
```

The pipelines (`internal/k8s/pipeline.go`, `internal/checkmk/pipeline.go`)
already have the severity (they use `policy.ModelFor(severity)`) and pass
`alert.SeverityLevel` down. `RecordClaudeUsage` receives the typed
`Severity` and uses `severity.String()` for the label.

### `internal/shared/interfaces.go` API change

The `Analyzer` and `ToolLoopRunner` interfaces gain the same `severity Severity`
parameter:

```go
type Analyzer interface {
    Analyze(ctx context.Context, severity Severity,
        model, systemPrompt, userPrompt string) (string, error)
}

type ToolLoopRunner interface {
    RunToolLoop(ctx context.Context, severity Severity,
        model, systemPrompt, userPrompt string,
        tools []anthropic.ToolUnionParam, maxRounds int,
        handleTool func(name string, input json.RawMessage) (string, error),
    ) (analysis string, rounds int, exhausted bool, err error)
}
```

All implementations of these interfaces (the real `ClaudeClient` plus any
test doubles in `internal/k8s/agent_test.go`,
`internal/checkmk/agent_test.go`, and pipeline tests) must update their
method signatures to match. The compiler will catch every site.

### `internal/shared/severity.go` — already exists, scope clarification

The `Severity` type is an `int` enum:

```go
type Severity int

const (
    SeverityUnknown Severity = iota  // 0 — zero-value, label = "unknown"
    SeverityInfo
    SeverityWarning
    SeverityCritical
)

func (s Severity) String() string  // returns "unknown" / "info" / "warning" / "critical"
```

`SeverityFromAlertmanager` and `SeverityFromCheckMK` are the production
constructors and never return `SeverityUnknown` (they default unknown input
to `SeverityWarning`).

**However**, the zero value `SeverityUnknown` is reachable: tests construct
`AlertPayload{}` literals without `SeverityLevel`, and any code path that
forgets to set the field gets `unknown`. The Prometheus label set therefore
includes `unknown` as a possible value.

Decision: **document `unknown` as a valid `severity` label value** rather
than fight the zero-value. The metric description for
`alert_anaylzer_alerts_processed_total` and `alert_analyzer_claude_tokens_total`
notes the four possible values. Tests that synthesize alerts and assert on
specific severity series MUST set `SeverityLevel` explicitly via the
helpers.

### Server / transport call-site updates

Direct uses of `source` outside `claude.go`:

- `cmd/k8s-analyzer/main.go:138`:
  `metrics.Prom.ClaudeAPIDuration.WithLabelValues("k8s")` → after the
  source-label drop, `ClaudeAPIDuration` becomes `prometheus.Histogram`
  (no `WithLabelValues`). Change to `metrics.Prom.ClaudeAPIDuration` direct
  reference.
- `cmd/checkmk-analyzer/main.go`: equivalent change.
- `internal/shared/server.go:90`: `s.metrics.MetricsHandler()` →
  `promhttp.HandlerFor(s.metrics.Prom.Registry(), promhttp.HandlerOpts{})`
  with a nil-Prom guard that returns the empty-body handler.
- **Counter ownership map:** today `server.go` increments enqueue/drop
  counters when alerts arrive on the queue. After the refactor, ownership
  is split by responsibility:
  - **Handlers** (`internal/k8s/handler.go`, `internal/checkmk/handler.go`)
    own `RecordEnqueued` / `RecordDropped` / `RecordResolved` /
    `RecordWebhookOutcome` — they have the per-alert and per-request context.
  - **Server** (`internal/shared/server.go`) owns only `SetQueueDepth` —
    it owns the queue state. It stops calling enqueue/drop counter methods.
    `Server.process` has no error return, so it cannot own failure counters.
  - **Pipelines** (`internal/k8s/pipeline.go`, `internal/checkmk/pipeline.go`)
    own `RecordFailed` / `ObserveProcessingDuration` / `RecordProcessed` —
    they bracket the analyze+publish work and observe success vs. failure.
  Any old `metrics.AlertsQueued.Add(1)` / `metrics.AlertsQueueFull.Add(1)`
  increments in `server.go` are removed.
- All call sites of `RecordAnalyzed(source, severity)` /
  `RecordCooldown(source)` / `SetQueueDepth(source, depth)` /
  `RecordClaudeAPIError(source)` / `RecordNtfyPublishError(source)` /
  `RecordAgentToolCall(source, tool, outcome, dur)` /
  `RecordAgentRounds(source, rounds, exhausted)` /
  `SetStormMode(source, active)` / `SetBreakerState(source, state)`:
  drop the source argument.
- `RecordAnalyzed(source, severity string)` is renamed to
  `RecordProcessed(severity Severity)` (signature already implied above).

### `cmd/*/main.go` updates

```go
// k8s-analyzer
prom, err := shared.NewPrometheusMetrics(shared.ProductK8s)
if err != nil {
    slog.Error("metrics init failed", "error", err)
    os.Exit(1)
}
metrics := shared.NewAlertMetrics(prom)
slog.Info("metrics initialized",
    "prefix", "alert_analyzer_*",
    "product", shared.ProductK8s.String())
```

The checkmk binary uses `ProductCheckMK`. The `LimitedTransport`
construction (which used `metrics.Prom.ClaudeAPIDuration.WithLabelValues("k8s")`)
becomes `metrics.Prom.ClaudeAPIDuration` (direct histogram, no per-call labels).

## Invariants

The design assumes — and the tests enforce — three operational invariants:

1. **One product per process, one private registry per process.** Running
   both binaries in one process is unsupported and would result in
   semantically wrong duplicate `go_*` / `process_*` series under different
   `product` values. Only the `cmd/*/main.go` entrypoints construct a
   registry.
2. **No default-registry usage.** `go_*` and `process_*` collectors MUST
   register only via the `WrapRegistererWith` wrapper around the private
   `prometheus.Registry`. Nothing else may register on
   `prometheus.DefaultRegisterer`. The test that enforces this calls
   `prometheus.DefaultGatherer.Gather()` before and after
   `NewPrometheusMetrics(...)` and compares the **set of metric family
   names** (not full proto equality — the default registry may legitimately
   have entries from indirect dependencies that vary between Go versions).
   Any new family name in the second snapshot is a leak.
3. **Severity label uses only `Severity.String()` values.** That means
   `unknown`, `info`, `warning`, `critical`. The `prom_metrics_test.go`
   test exercises every typed `Severity` value through
   `RecordProcessed`/`RecordClaudeUsage` and asserts the resulting label
   set is exactly that closed set — no raw input strings ever flow into the
   label.

## Tests

- `internal/shared/severity_test.go` — already exists; no change needed
  beyond verifying the four-value enum.
- `internal/shared/dropreason_test.go` — NEW (small). Asserts the four
  `DropReason` constants exist and round-trip via `string()`.
- `internal/shared/webhook_outcome_test.go` — NEW (small). Same shape.
- `internal/shared/cooldown_test.go` — extend with explicit `CooldownOutcome`
  cases:
  - Cold path → `CooldownAccepted`.
  - Fingerprint already in cooldown → `CooldownFingerprint`, group entry
    not set (rollback verified via internal map state or follow-up call).
  - Group already in cooldown → `CooldownGroup`, fingerprint entry not set.
  - `groupKey == ""` mode → only `CooldownAccepted` or `CooldownFingerprint`
    is reachable (test asserts `CooldownGroup` is never returned).
- `internal/shared/metrics_test.go` — replace text-format assertions with
  - `TestAlertMetricsNilSafe`: every method on `nil` receiver and on
    `&AlertMetrics{Prom: nil}` is a no-op.
  - `TestAlertMetricsDelegation`: each method increments / observes the
    correct Prometheus instrument when `Prom` is set.
- `internal/shared/prom_metrics_test.go` — NEW. For each product:
  - Assert all expected metric names are registered.
  - Assert `product` `ConstLabel` value matches the constructor argument.
  - Walk every per-call label value (every drop reason, every token kind,
    every webhook outcome, every tool outcome).
  - Default-registry leak check (Gather-before / Gather-after).
  - Severity label-set check (closed enum).
- `internal/shared/server_test.go` — `TestServer_BuildMetricsMux` (line 95)
  is rewritten:
  - Construct with `AlertMetrics{Prom: nil}`, assert handler returns 200
    with `Content-Type: text/plain; version=0.0.4` and empty body.
  - Construct with `AlertMetrics{Prom: realProm}` after some
    `metrics.RecordWebhookOutcome(...)` calls; assert handler output
    contains the expected metric names.
- `internal/k8s/handler_test.go`, `internal/checkmk/handler_test.go` — add
  cases for each webhook outcome (auth_failed, payload_invalid,
  payload_too_large, unavailable) and each drop reason.
- All `*_test.go` files that pass `"k8s"` / `"checkmk"` as the first
  `WithLabelValues` arg or as a source argument to `Record*`/`Set*` — drop
  that arg.

## Dashboard Strategy

`deploy/grafana/claude-alert-analyzer.json`:

- Remove the `source` template variable.
- Add a `product` template variable populated by
  `label_values(alert_analyzer_alerts_processed_total, product)`. Values:
  `k8s`, `checkmk`. Multi-select + `All` enabled.
- All panel queries change from `{source=~"$source", ...}` to
  `{product=~"$product", ...}`.
- The `severity` template variable's query updates to
  `label_values(alert_analyzer_alerts_processed_total{product=~"$product"}, severity)`.
- Token panel queries split by `kind`:
  - input: `sum by (kind) (rate(alert_analyzer_claude_tokens_total{kind="input", product=~"$product"}[5m]))`
  - cache hit rate:
    `sum(rate(...{kind="cache_read"}[5m])) / sum(rate(...{kind=~"input|cache_creation|cache_read"}[5m]))`
- New panels: `alert_analyzer_webhooks_total{outcome}` rate by outcome,
  `go_goroutines{product=~"$product"}` for runtime visibility.
- No string interpolation into metric names.

## Documentation Impact

- **`docs/observability.md`** — full rewrite of the metric tables. New
  tables list each metric once with `product` documented as a constant
  label. Includes a "PromQL filtering" subsection covering the
  `kind`-grouping caveat.
- **`docs/cost-and-storm-protection.md`** — every PromQL example references
  new metric names and adds `product=~"..."` filters where useful.
- **`CLAUDE.md`** — the "Metrics" line updates to reference the new naming.
- **`README.md`** — search for any metric-name references and update.
- **NEW: `docs/metrics-migration.md`** — operator-facing migration guide.
  Lists every old metric name, its new name, the PromQL substitutions for
  recording rules and Alertmanager rules. Linked from CHANGELOG.
- Old spec files in `docs/superpowers/specs/` are NOT retroactively edited.

## Migration / Breaking Change

- `/metrics` output changes completely; old names disappear in one release.
- **Major version bump.** Per semver, this is a breaking API change.
- CHANGELOG entry must list the full old→new mapping and link to
  `docs/metrics-migration.md`.
- Each binary prints a startup log line:
  `"metrics initialized" prefix=alert_analyzer_* product=k8s`. Operators
  upgrading without reading the release notes see the change in pod logs
  immediately.
- No dual-emission, no deprecation period.

## Implementation Order

The whole refactor is tightly coupled (renaming a Prometheus field implies
updating every call site, the dashboard, and the docs simultaneously). The
recommended ordering minimizes the time during which the working tree is
unbuildable:

1. **`internal/shared/` types and enums** —
   `product.go`, `dropreason.go`, `webhook_outcome.go`, the
   `CooldownOutcome` enum addition. Pure additions, no breakage.
2. **`prom_metrics.go` rewrite** — new constructor signature, all field
   renames, `ConstLabel(product=...)`, `WrapRegistererWith` for runtime
   collectors. Build now fails because old field names no longer exist.
3. **`metrics.go` `AlertMetrics` rewrite** — new method API, deletion of
   atomic fields and `MetricsHandler()`.
4. **`claude.go` and `cooldown.go` API changes** — severity threading,
   `CooldownOutcome` return.
5. **All call sites** — pipelines, handlers, agents, `server.go`,
   `cmd/*/main.go`.
6. **Tests** — rewrite each affected test file. Build is now green.
7. **Dashboard JSON + docs/observability.md + docs/cost-and-storm-protection.md
   + CHANGELOG + docs/metrics-migration.md.**

Steps 2–6 land as a single atomic PR (each by itself leaves the tree
unbuildable). Step 1 can land separately. Step 7 is a separate PR with no
runtime effect.

## Considered Alternatives

### Per-product prefix in the metric name (rejected)

Initial brainstorming choice. Each binary would emit
`alert_analyzer_k8s_*` or `alert_analyzer_checkmk_*` and drop the `source`
label entirely. Rejected on Codex Round-1 review:

- Not idiomatic Prometheus. `kube_*` and `alertmanager_*` identify the
  exporter project, not a runtime product dimension.
- Federation, recording rules across products, single-LB scrape jobs all
  break or get harder.
- Dashboards become complicated: every metric reference needs string
  interpolation, the `severity` template variable's underlying query also
  breaks, panel reuse across products requires duplication.

### `DropState` boolean struct + `ClassifyDrop` precedence helper (rejected)

Initial fix-up for the duplicated cooldown counters. Rejected on Codex
Round-2 review: not implementable on top of today's bool-returning
`CheckAndSetWithGroup` without re-probing (which reintroduces the race the
combined API was created to avoid), and the default-to-`queue_full`
fallback silently masks caller bugs. Replaced with the structured
`CooldownOutcome` return + sequential handler dispatch above.

### Dual-emission / deprecation phase (rejected)

Emit both old and new names for one release. Rejected: doubles cardinality
during transition; adds code that has to be torn out later; the operator
base is small enough that a major version bump plus a migration document is
sufficient.

## Out of Scope (deferred)

- Saturation / utilization metrics (queue-fill ratio, worker-busy ratio).
- Queue-age histogram (alert-arrives → alert-dequeued latency).
- p999 percentile-of-percentiles for cross-instance aggregation.
- Adding `claude_api_duration_seconds` labels for the `model` dimension.
- Adding a `phase` label to `alerts_failed_total` (pre_api / api / post_api).
