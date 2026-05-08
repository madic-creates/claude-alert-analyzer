# Observability

## API endpoints

Both analyzers expose two HTTP servers.

**Main server** (`PORT`, default `8080`)

- `GET /health` — liveness probe, returns `200 ok`
- `POST /webhook` — alert receiver, requires `Authorization: Bearer <WEBHOOK_SECRET>`

**Metrics server** (`METRICS_PORT`, default `9101`)

- `GET /metrics` — Prometheus metrics, no authentication required

## Metrics

All application metrics share the prefix `alert_analyzer_*` and carry a
constant `product` label (`k8s` or `checkmk`) applied at registry construction.
Standard Go runtime and process collectors (`go_*`, `process_*`) are also
registered on the same registry with the same `product` label so the entire
metric surface is uniformly addressable.

### Pipeline

| Metric | Type | Per-call labels | Description |
|---|---|---|---|
| `alert_analyzer_webhooks_total` | counter | `outcome` | `/webhook` HTTP outcomes (one per request, after the final HTTP status is decided) |
| `alert_analyzer_alerts_enqueued_total` | counter | — | Alerts placed on the work queue |
| `alert_analyzer_alerts_dropped_total` | counter | `reason` | Alerts dropped before reaching the queue |
| `alert_analyzer_alerts_resolved_total` | counter | — | k8s `resolved` skips and CheckMK `RECOVERY` skips |
| `alert_analyzer_alerts_processed_total` | counter | `severity` | Alerts successfully analyzed and published |
| `alert_analyzer_alerts_failed_total` | counter | — | Alerts where analysis or publishing failed |
| `alert_analyzer_processing_duration_seconds` | histogram | — | End-to-end per-alert processing time |
| `alert_analyzer_queue_depth` | gauge | — | Current alerts waiting in the work queue |

`outcome` is one of `accepted` (HTTP 2xx), `auth_failed` (401),
`payload_invalid` (400), `payload_too_large` (413), `unavailable` (503),
`internal_error` (5xx).

`reason` is one of `queue_full`, `invalid_fingerprint`, `cooldown`,
`group_cooldown`. Each admission step emits exactly one reason — there is no
precedence helper.

`severity` is one of `unknown`, `info`, `warning`, `critical` (the four
values returned by `shared.Severity.String()`).

### Claude API & tokens

| Metric | Type | Per-call labels | Description |
|---|---|---|---|
| `alert_analyzer_claude_api_duration_seconds` | histogram | — | Claude API call latency |
| `alert_analyzer_claude_api_errors_total` | counter | — | Claude API errors |
| `alert_analyzer_claude_tokens_total` | counter | `kind`, `severity`, `model` | Cumulative Claude API tokens |

`kind` is one of `input`, `output`, `cache_creation`, `cache_read`. The four
kinds replace the four separate `claude_*_tokens_total` counters from earlier
releases.

> **PromQL caveat.** `sum(rate(alert_analyzer_claude_tokens_total[5m]))`
> *without* a `by (kind)` grouping is semantically meaningless because it adds
> different cost categories. Every dashboard panel and recording rule that
> uses this metric MUST filter or group by `kind`. See
> [`cost-and-storm-protection.md`](cost-and-storm-protection.md) for cache-hit-rate
> and per-model cost queries.

### Agentic tool loop

| Metric | Type | Per-call labels | Description |
|---|---|---|---|
| `alert_analyzer_agent_tool_calls_total` | counter | `tool`, `outcome` | Tool calls made inside the agentic Claude loop |
| `alert_analyzer_agent_tool_duration_seconds` | histogram | `tool` | Per-tool wall-clock latency |
| `alert_analyzer_agent_rounds_per_run` | histogram | — | Tool rounds Claude actually used per completed loop |
| `alert_analyzer_agent_rounds_exhausted_total` | counter | — | Loops that ended via forced summary because `MAX_AGENT_ROUNDS` was reached |

### Storm robustness

| Metric | Type | Per-call labels | Description |
|---|---|---|---|
| `alert_analyzer_storm_mode_active` | gauge | — | `1` when the storm-mode threshold is exceeded, `0` otherwise |
| `alert_analyzer_claude_circuit_breaker_state` | gauge | — | Circuit-breaker state: `0`=closed, `1`=open, `2`=half-open |
| `alert_analyzer_notify_aggregator_drops_total` | counter | `aggregator` | Alerts dropped by `NotifyAggregator` (`storm` or `breaker`) |

### External I/O

| Metric | Type | Per-call labels | Description |
|---|---|---|---|
| `alert_analyzer_ntfy_publish_errors_total` | counter | — | ntfy publish failures |

### Runtime / process

Standard `prometheus/client_golang` collectors registered via
`WrapRegistererWith` so each series carries the same `product` constant
label as the application metrics:

| Family | Coverage |
|---|---|
| `go_*` | Goroutine count, GC stats, memory allocator metrics |
| `process_*` | CPU, virtual memory, resident memory, file descriptors, uptime |

### Example scrape config

```yaml
- job_name: claude-alert-analyzer
  static_configs:
    - targets: ['claude-alert-analyzer.monitoring:9101']
```

The `product` label is applied at registry construction and arrives in every
sample, so no extra Prometheus relabeling is required.

## Logging

Structured JSON logs to stdout via Go's `slog`. Verbosity is controlled by
`LOG_LEVEL` (`debug`, `info`, `warn`, `error`). Collect with whichever log
pipeline you already use.

Each binary prints a startup line confirming the metric prefix and product so
operators upgrading without reading release notes see the change immediately:

```
metrics initialized prefix=alert_analyzer_* product=k8s
```
