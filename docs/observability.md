# Observability

## API endpoints

Both analyzers expose two HTTP servers.

**Main server** (`PORT`, default `8080`)

- `GET /health` — liveness probe, returns `200 ok`
- `POST /webhook` — alert receiver, requires `Authorization: Bearer <WEBHOOK_SECRET>`

**Metrics server** (`METRICS_PORT`, default `9101`)

- `GET /metrics` — Prometheus metrics, no authentication required

## Metrics

The `/metrics` endpoint exposes Prometheus-format data in two sections.

### Operational counters

Unlabeled, always present:

| Metric | Type | Description |
|--------|------|-------------|
| `alert_analyzer_webhooks_received_total` | counter | Total webhook requests received |
| `alert_analyzer_alerts_queued_total` | counter | Alerts enqueued for processing |
| `alert_analyzer_alerts_queue_full_total` | counter | Alerts dropped because queue was full |
| `alert_analyzer_alerts_cooldown_total` | counter | Alerts skipped due to active cooldown |
| `alert_analyzer_alerts_processed_total` | counter | Alerts successfully analyzed and published |
| `alert_analyzer_alerts_failed_total` | counter | Alerts where analysis or publishing failed |
| `alert_analyzer_processing_duration_seconds` | summary | Processing time per alert |

### Labeled metrics

With `source` and/or `severity`:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `alerts_analyzed_total` | counter | `source`, `severity` | Alerts successfully analyzed |
| `alerts_cooldown_total` | counter | `source` | Alerts skipped due to active cooldown |
| `queue_depth` | gauge | `source` | Current alerts waiting in the work queue |
| `claude_api_duration_seconds` | histogram | — | Claude API call latency |
| `claude_api_errors_total` | counter | `source` | Claude API errors |
| `ntfy_publish_errors_total` | counter | `source` | ntfy publish failures |
| `claude_input_tokens_total` | counter | `source`, `severity`, `model` | Claude API input tokens (excluding cache hits) |
| `claude_output_tokens_total` | counter | `source`, `severity`, `model` | Claude API output tokens |
| `claude_cache_creation_tokens_total` | counter | `source`, `severity`, `model` | Tokens that created cache entries (~25% surcharge) |
| `claude_cache_read_tokens_total` | counter | `source`, `severity`, `model` | Tokens served from cache (~10% of regular input cost) |

`source` is `k8s` or `checkmk`. The four `claude_*_tokens_total` counters drive cache-hit-rate and cost dashboards — see [cost-and-storm-protection.md](cost-and-storm-protection.md) for ready-made PromQL queries.

### Example scrape config

```yaml
- job_name: claude-alert-analyzer
  static_configs:
    - targets: ['claude-alert-analyzer.monitoring:9101']
```

## Logging

Structured JSON logs to stdout via Go's `slog`. Verbosity is controlled by `LOG_LEVEL` (`debug`, `info`, `warn`, `error`). Collect with whichever log pipeline you already use.
