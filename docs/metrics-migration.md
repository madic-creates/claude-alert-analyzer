# Metrics Migration Guide

This release renames every Prometheus metric exposed by the analyzers. There
is **no dual-emission and no deprecation period** — all old names disappear
in this version. Update your dashboards, recording rules, and Alertmanager
rules before deploying.

The bundled Grafana dashboard at
[`deploy/grafana/claude-alert-analyzer.json`](../deploy/grafana/claude-alert-analyzer.json)
is updated for the new metric names. Re-import it after upgrading.

## What changed at a glance

- **Single uniform prefix.** Every application metric now starts with
  `alert_analyzer_*`. Standard Go runtime / process collectors (`go_*`,
  `process_*`) are also exposed.
- **`source` label replaced by `product`.** Each binary applies its product
  identity as a `ConstLabel` at registry construction. Values: `k8s`,
  `checkmk`. The label arrives in every sample without per-call argument
  passing.
- **Drop counters consolidated.** `cooldown`, `queue_full`,
  `invalid_fingerprint`, and the new `group_cooldown` reasons are all on a
  single `alerts_dropped_total{reason}` metric.
- **Token counters consolidated.** Four counters (`input`, `output`,
  `cache_creation`, `cache_read`) collapsed into one
  `claude_tokens_total{kind, severity, model}` metric.
- **Severity is real.** Previously hardcoded to `"all"`; now carries the
  per-call value (`unknown`, `info`, `warning`, `critical`).
- **Webhook outcomes added.** New `webhooks_total{outcome}` metric replaces
  the unlabeled `webhooks_received_total` and surfaces 401/400/413/503
  paths that were invisible before.
- **Resolved/recovery counter added.** New
  `alerts_resolved_total` tracks k8s `resolved` skips and CheckMK `RECOVERY`
  skips — separate from drops.
- **Processing duration is now a histogram.** Previously a summary. Quantile
  estimation is now meaningful across instances.
- **Hand-rolled `/metrics` exposition removed.** The endpoint is now served
  via `promhttp.HandlerFor` for the standard Prometheus output format.

## Rename map

### Pipeline

| Old | New |
|---|---|
| `alert_analyzer_webhooks_received_total` | `alert_analyzer_webhooks_total{outcome}` (sum over `outcome`) |
| `alert_analyzer_alerts_queued_total` | `alert_analyzer_alerts_enqueued_total` |
| `alert_analyzer_alerts_queue_full_total` | `alert_analyzer_alerts_dropped_total{reason="queue_full"}` |
| `alert_analyzer_alerts_invalid_fingerprint_total` | `alert_analyzer_alerts_dropped_total{reason="invalid_fingerprint"}` |
| `alert_analyzer_alerts_cooldown_total` | `alert_analyzer_alerts_dropped_total{reason="cooldown"}` |
| `alerts_cooldown_total{source}` | `alert_analyzer_alerts_dropped_total{reason="cooldown", product}` |
| `alert_analyzer_alerts_processed_total` | `alert_analyzer_alerts_processed_total{severity, product}` |
| `alerts_analyzed_total{source, severity}` | `alert_analyzer_alerts_processed_total{severity, product}` |
| `alert_analyzer_alerts_failed_total` | `alert_analyzer_alerts_failed_total{product}` |
| `alert_analyzer_processing_duration_seconds` (summary) | `alert_analyzer_processing_duration_seconds` (**histogram**) |
| `queue_depth{source}` | `alert_analyzer_queue_depth{product}` |

### Claude API & tokens

| Old | New |
|---|---|
| `claude_api_duration_seconds{source}` | `alert_analyzer_claude_api_duration_seconds{product}` |
| `claude_api_errors_total{source}` | `alert_analyzer_claude_api_errors_total{product}` |
| `claude_input_tokens_total{source, severity, model}` | `alert_analyzer_claude_tokens_total{kind="input", severity, model, product}` |
| `claude_output_tokens_total{source, severity, model}` | `alert_analyzer_claude_tokens_total{kind="output", ...}` |
| `claude_cache_creation_tokens_total{source, severity, model}` | `alert_analyzer_claude_tokens_total{kind="cache_creation", ...}` |
| `claude_cache_read_tokens_total{source, severity, model}` | `alert_analyzer_claude_tokens_total{kind="cache_read", ...}` |

### Agentic tool loop

| Old | New |
|---|---|
| `agent_tool_calls_total{source, tool, outcome}` | `alert_analyzer_agent_tool_calls_total{tool, outcome, product}` |
| `agent_tool_duration_seconds{source, tool}` | `alert_analyzer_agent_tool_duration_seconds{tool, product}` |
| `agent_rounds_used{source}` | `alert_analyzer_agent_rounds_per_run{product}` |
| `agent_rounds_exhausted_total{source}` | `alert_analyzer_agent_rounds_exhausted_total{product}` |

### Storm robustness

| Old | New |
|---|---|
| `storm_mode_active{source}` | `alert_analyzer_storm_mode_active{product}` |
| `claude_circuit_breaker_state{source}` | `alert_analyzer_claude_circuit_breaker_state{product}` |
| `notify_aggregator_drops_total{aggregator}` | `alert_analyzer_notify_aggregator_drops_total{aggregator, product}` |

### External I/O

| Old | New |
|---|---|
| `ntfy_publish_errors_total{source}` | `alert_analyzer_ntfy_publish_errors_total{product}` |

### New metrics

| Metric | Purpose |
|---|---|
| `alert_analyzer_alerts_resolved_total{product}` | k8s `resolved` skips + CheckMK `RECOVERY` skips (separate from drops) |
| `alert_analyzer_webhooks_total{outcome, product}` | HTTP-level webhook outcomes (401/400/413/503 surface here, no longer invisible) |
| `go_*{product}`, `process_*{product}` | Standard Go runtime / process collectors |

## PromQL substitutions

### Cache hit rate

**Before:**

```promql
sum(rate(claude_cache_read_tokens_total[5m]))
/
sum(
  rate(claude_cache_read_tokens_total[5m])
  + rate(claude_cache_creation_tokens_total[5m])
  + rate(claude_input_tokens_total[5m])
)
```

**After:**

```promql
sum(rate(alert_analyzer_claude_tokens_total{kind="cache_read"}[5m]))
/
sum(rate(alert_analyzer_claude_tokens_total{kind=~"input|cache_creation|cache_read"}[5m]))
```

### Storm-mode and breaker dwell time

**Before:**

```promql
storm_mode_active{source="k8s"} == 1
claude_circuit_breaker_state{source="checkmk"} == 1
```

**After:**

```promql
alert_analyzer_storm_mode_active{product="k8s"} == 1
alert_analyzer_claude_circuit_breaker_state{product="checkmk"} == 1
```

### Aggregator drops

**Before:**

```promql
sum by (aggregator) (rate(notify_aggregator_drops_total[5m]))
```

**After:**

```promql
sum by (aggregator) (rate(alert_analyzer_notify_aggregator_drops_total[5m]))
```

### Cooldown drops by source

**Before:**

```promql
sum by (source) (rate(alerts_cooldown_total[5m]))
```

**After (now also distinguishes fingerprint vs group cooldown):**

```promql
sum by (product, reason) (
  rate(alert_analyzer_alerts_dropped_total{reason=~"cooldown|group_cooldown"}[5m])
)
```

## Important PromQL caveats

`alert_analyzer_claude_tokens_total` is **one metric, four kinds**. PromQL
like `sum(rate(alert_analyzer_claude_tokens_total[5m]))` *without* a
`by (kind)` clause adds different cost categories and is semantically
meaningless. Always group or filter by `kind`.

`alert_analyzer_webhooks_total` is **per-request, per-outcome**. The
unlabeled count of received webhooks is now
`sum(rate(alert_analyzer_webhooks_total{product=~"..."}[5m]))`.

## Verification after upgrade

Both binaries print a startup log line confirming the new prefix and product:

```
metrics initialized prefix=alert_analyzer_* product=k8s
```

Sanity-check the live `/metrics` output:

```bash
curl -s localhost:9101/metrics | grep -E '^alert_analyzer_|^go_|^process_' | head -20
```

Every line should start with `alert_analyzer_`, `go_`, or `process_`. No old
names (`alerts_analyzed_total`, `claude_input_tokens_total`, etc.) should
appear.
