# Configuration

Environment-variable reference for both analyzers.

## Shared

| Variable | Default | Description |
|----------|---------|-------------|
| `WEBHOOK_SECRET` | **(required)** | Bearer token for webhook authentication |
| `ANTHROPIC_API_KEY` | **(one of)** | Anthropic API key (sets `x-api-key` header). Exactly one of this or `ANTHROPIC_AUTH_TOKEN` must be set; both-set is a fatal error at startup |
| `ANTHROPIC_AUTH_TOKEN` | **(one of)** | OpenRouter or compatible API token (sets `Authorization: Bearer` header) |
| `ANTHROPIC_BASE_URL` | `https://api.anthropic.com/` | LLM API endpoint base. The SDK appends `/v1/messages` itself, so do not include the path here |
| `CLAUDE_MODEL` | `claude-sonnet-4-6` | Model ID for analysis |
| `PORT` | `8080` | HTTP listen port for `/health` and `/webhook` |
| `METRICS_PORT` | `9101` | Port for the Prometheus `/metrics` endpoint |
| `COOLDOWN_SECONDS` | `300` | Seconds before re-analyzing the same alert |
| `NTFY_PUBLISH_URL` | `https://ntfy.example.com` | ntfy server URL |
| `NTFY_PUBLISH_TOPIC` | *(varies per analyzer)* | ntfy topic name |
| `NTFY_PUBLISH_TOKEN` | *(empty)* | ntfy auth token (optional) |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `MAX_AGENT_ROUNDS` | `10` | Max tool-loop rounds per agentic analysis (1–50). Per-severity overrides (`MAX_AGENT_ROUNDS_<SEVERITY>`) accept `0` for static-only mode — see [cost-and-storm-protection.md](cost-and-storm-protection.md) |

## K8s analyzer

| Variable | Default | Description |
|----------|---------|-------------|
| `PROMETHEUS_URL` | `http://kube-prometheus-stack-prometheus.monitoring.svc.cluster.local:9090` | Prometheus endpoint |
| `MAX_LOG_BYTES` | `2048` | Per-pod log truncation limit |
| `SKIP_RESOLVED` | `true` | Ignore resolved alerts |
| `NTFY_PUBLISH_TOPIC` | `kubernetes-analysis` | Default ntfy topic |
| `KUBE_API_TIMEOUT` | `30s` | Deadline applied to all Kubernetes API calls during context gathering (events + pod status + logs share this budget). Go `time.ParseDuration` syntax (e.g. `30s`, `1m`). Empty or `0` uses the default |
| `PROM_TIMEOUT` | `30s` | Deadline applied to Prometheus metric queries during context gathering. Go `time.ParseDuration` syntax. Empty or `0` uses the default |

## CheckMK analyzer

| Variable | Default | Description |
|----------|---------|-------------|
| `CHECKMK_API_URL` | `http://checkmk-service.monitoring:5000/cmk/check_mk/api/1.0/` | CheckMK REST API URL |
| `CHECKMK_API_USER` | **(required)** | CheckMK automation user |
| `CHECKMK_API_SECRET` | **(required)** | CheckMK automation secret |
| `SSH_ENABLED` | `true` | Enable agentic SSH diagnostics (`false` = analyze without SSH) |
| `SSH_USER` | `nagios` | SSH user for host diagnostics |
| `SSH_KEY_PATH` | `/ssh/id_ed25519` | Path to SSH private key |
| `SSH_KNOWN_HOSTS_PATH` | `/ssh/known_hosts` | Path to known_hosts file |
| `SSH_DENIED_COMMANDS` | *(built-in default)* | Comma-separated denylist. Empty = no guardrails. See [`DefaultDeniedCommands`](../internal/checkmk/agent.go) for the current default list |
| `NTFY_PUBLISH_TOPIC` | `checkmk-analysis` | Default ntfy topic |
| `CHECKMK_API_TIMEOUT` | `10s` | HTTP-client timeout for CheckMK REST API requests. Go `time.ParseDuration` syntax (e.g. `10s`, `30s`). Empty or non-positive value uses the default; explicit `0` does **not** disable the timeout |

The default denylist is defined in [`internal/checkmk/agent.go`](../internal/checkmk/agent.go) as `DefaultDeniedCommands` — consult the source for the authoritative, always-current list. It covers destructive filesystem commands, privilege escalation, process/user management, networking and mount tools, shells and interpreters, and similar classes.

`systemctl` is a special case: when denied, read-only subcommands (`status`, `show`, `is-active`, `is-failed`, `is-enabled`, `list-units`, `list-unit-files`, `list-timers`, `list-sockets`, `list-dependencies`) are still allowed.

## LLM provider

The analyzer talks to the Anthropic Messages API via the official `anthropic-sdk-go` client. Configure auth via env vars:

- `ANTHROPIC_API_KEY` — sets `x-api-key` header (Anthropic's native scheme)
- `ANTHROPIC_AUTH_TOKEN` — sets `Authorization: Bearer` header (required for OpenRouter)
- `ANTHROPIC_BASE_URL` — optional; default is the Anthropic API. Set to `https://openrouter.ai/api` for OpenRouter.

Exactly one of `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN` must be set at startup. Response tokens are capped at 2048 (`Analyze`) / 4096 (tool-loop rounds).

## Storm robustness (optional)

All disabled by default. See [cost-and-storm-protection.md](cost-and-storm-protection.md) for the recommended rollout sequence and operator guidance.

| Variable | Default | Description |
|----------|---------|-------------|
| `GROUP_COOLDOWN_SECONDS` | `0` | Coarser dedup: alertname+namespace (k8s) / host+service (checkmk). `0` = disabled |
| `STORM_MODE_THRESHOLD` | `0` | Alerts/5min before forcing rounds=0 + aggregated ntfy. `0` = disabled |
| `STORM_MODE_NOTIFY_INTERVAL` | `60s` | Storm-aggregator emit interval |
| `CIRCUIT_BREAKER_THRESHOLD` | `0` | Consecutive analysis failures before open. `0` = disabled |
| `CIRCUIT_BREAKER_OPEN_SECONDS` | `60` | Open-state duration |
| `CIRCUIT_BREAKER_MAX_PROBE_SECONDS` | `60` | Half-open probe watchdog timeout |
| `CIRCUIT_BREAKER_NOTIFY_INTERVAL` | `300s` | Breaker-aggregator emit interval |

## Alert history (optional)

Disabled by default. When enabled, every alert fire is recorded in a local
SQLite store and, on a re-fire, an "Alert Recurrence" section ("this fingerprint
has fired N times in the last 6h") is prepended to the Claude prompt. Best-effort:
store errors are logged + counted as metrics, never block analysis. See
[the design spec](superpowers/specs/2026-05-30-alert-history-cross-alert-context-design.md).

| Variable | Default | Description |
|----------|---------|-------------|
| `HISTORY_ENABLED` | `false` | Master switch. `false` = no store, no disk I/O |
| `HISTORY_DB_PATH` | `/var/lib/analyzer/history.db` | SQLite file path. Requires a writable volume (PVC) mounted at the parent directory |
| `HISTORY_TTL` | `6h` | Lookback window for the recurrence count **and** the prune horizon. Go `time.ParseDuration` syntax (e.g. `6h`, `24h`, `168h` for "this week") |
| `HISTORY_MAX_ENTRIES` | `5` | Max prior analyses surfaced in the prompt (1–100). Used by Phase B prior-summary injection |
| `HISTORY_INJECT_PRIOR` | `true` | Inject prior-analysis summaries (Phase B). `false` = recurrence metadata only |

**Single replica only:** the store uses SQLite with a single writer and a
ReadWriteOnce PVC. Scaling beyond one replica requires an external store (not
supported). The bundled deployment manifests
(`deploy/k8s-analyzer/`, `deploy/checkmk-analyzer/`) already provision the PVC
and mount at `/var/lib/analyzer`. History metrics (`alert_analyzer_history_*`)
are documented in [observability.md](observability.md).
