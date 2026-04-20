# Claude Alert Analyzer

LLM-powered root-cause analysis for monitoring alerts. Receives webhooks from Alertmanager (Kubernetes) or CheckMK, automatically gathers diagnostic context, sends it to Claude for analysis, and delivers the result via [ntfy](https://ntfy.sh).

## How It Works

```
Alert fires → Webhook → Gather diagnostics → Claude API → ntfy notification
```

Two independent analyzers share a common library but run as separate binaries:

| Analyzer | Alert Source | Diagnostics Gathered |
|----------|-------------|---------------------|
| **k8s-analyzer** | Alertmanager | Prometheus metrics, K8s events, pod status, pod logs |
| **checkmk-analyzer** | CheckMK notification script | CheckMK REST API (host/service details), SSH diagnostics |

Both analyzers deduplicate alerts (configurable cooldown) and process them concurrently (5 workers, queue depth 20).

## Quick Start

### Prerequisites

- An [Anthropic API key](https://console.anthropic.com/) (or OpenRouter API key)
- An [ntfy](https://ntfy.sh) server for receiving analysis results
- **k8s-analyzer**: Kubernetes cluster with Alertmanager
- **checkmk-analyzer**: CheckMK instance with automation user credentials

### Container Images

Pre-built images are published to GHCR on every push to `main`:

```
ghcr.io/madic-creates/claude-alert-kubernetes-analyzer:latest
ghcr.io/madic-creates/claude-alert-checkmk-analyzer:latest
```

Both are also tagged with the short commit SHA (e.g. `:a1b2c3d`).

| Image | Base | Size |
|-------|------|------|
| `claude-alert-kubernetes-analyzer` | `scratch` | ~13 MB |
| `claude-alert-checkmk-analyzer` | `alpine:3.21` | ~25 MB (includes openssh-client) |

### API Endpoints

Both analyzers expose two HTTP servers:

**Main server** (`PORT`, default `8080`):
- `GET /health` -- liveness/readiness probe (returns `200 ok`)
- `GET /ready` -- readiness probe with dependency checks
- `POST /webhook` -- alert receiver (requires `Authorization: Bearer <WEBHOOK_SECRET>`)

**Metrics server** (`METRICS_PORT`, default `9101`):
- `GET /metrics` -- Prometheus metrics (no authentication required)

## Configuration

### Shared Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WEBHOOK_SECRET` | **(required)** | Bearer token for webhook authentication |
| `API_KEY` | **(required)** | Anthropic or OpenRouter API key |
| `API_BASE_URL` | `https://api.anthropic.com/v1/messages` | LLM API endpoint |
| `CLAUDE_MODEL` | `claude-sonnet-4-6` | Model to use for analysis |
| `PORT` | `8080` | HTTP listen port for `/health`, `/ready`, and `/webhook` |
| `METRICS_PORT` | `9101` | Port for the Prometheus `/metrics` endpoint |
| `COOLDOWN_SECONDS` | `300` | Seconds before re-analyzing the same alert |
| `NTFY_PUBLISH_URL` | `https://ntfy.example.com` | ntfy server URL |
| `NTFY_PUBLISH_TOPIC` | *(varies per analyzer)* | ntfy topic name |
| `NTFY_PUBLISH_TOKEN` | *(empty)* | ntfy auth token (optional) |
| `LOG_LEVEL` | `info` | Log verbosity: `debug`, `info`, `warn`, `error` |

### K8s Analyzer

| Variable | Default | Description |
|----------|---------|-------------|
| `PROMETHEUS_URL` | `http://kube-prometheus-stack-prometheus.monitoring.svc.cluster.local:9090` | Prometheus endpoint |
| `ALLOWED_NAMESPACES` | `monitoring,databases,media` | Namespaces allowed for pod log collection |
| `MAX_LOG_BYTES` | `2048` | Per-pod log truncation limit |
| `SKIP_RESOLVED` | `true` | Ignore resolved alerts |
| `NTFY_PUBLISH_TOPIC` | `kubernetes-analysis` | Default ntfy topic |

The k8s-analyzer uses in-cluster config (`rest.InClusterConfig()`) and must run inside the Kubernetes cluster.

### CheckMK Analyzer

| Variable | Default | Description |
|----------|---------|-------------|
| `CHECKMK_API_URL` | `http://checkmk-service.monitoring:5000/cmk/check_mk/api/1.0/` | CheckMK REST API URL |
| `CHECKMK_API_USER` | **(required)** | CheckMK automation user |
| `CHECKMK_API_SECRET` | **(required)** | CheckMK automation secret |
| `SSH_ENABLED` | `true` | Enable agentic SSH diagnostics (`false` = analyze without SSH) |
| `SSH_USER` | `nagios` | SSH user for host diagnostics |
| `SSH_KEY_PATH` | `/ssh/id_ed25519` | Path to SSH private key |
| `SSH_KNOWN_HOSTS_PATH` | `/ssh/known_hosts` | Path to known_hosts file |
| `SSH_DENIED_COMMANDS` | *(see below)* | Comma-separated list of denied SSH commands. Empty = no guardrails |

Default denylist for `SSH_DENIED_COMMANDS` (used when the variable is not set):

```
rm,rmdir,dd,mkfs,mke2fs,shutdown,reboot,poweroff,halt,init,sudo,su,pkexec,doas,chmod,chown,chgrp,kill,killall,pkill,mv,cp,ln,useradd,userdel,usermod,groupadd,groupdel,passwd,crontab,iptables,ip6tables,nft,mount,umount,mkswap,swapon,swapoff,insmod,rmmod,modprobe,systemctl
```

`systemctl` is a special case: when denied, read-only subcommands (`status`, `show`, `is-active`, `is-failed`, `is-enabled`, `list-units`, `list-unit-files`, `list-timers`, `list-sockets`, `list-dependencies`) are still allowed.
| `MAX_AGENT_ROUNDS` | `10` | Max SSH command rounds per agentic analysis |
| `NTFY_PUBLISH_TOPIC` | `checkmk-analysis` | Default ntfy topic |

### LLM Provider Configuration

The Claude client auto-detects the provider from `API_BASE_URL`:

| Provider | Detection | Auth Header |
|----------|-----------|-------------|
| Anthropic | URL contains `anthropic.com` | `x-api-key` + `anthropic-version: 2023-06-01` |
| OpenRouter / other | Everything else | `Authorization: Bearer` |

## Setup Guides

### K8s Analyzer with Alertmanager

1. Deploy the `claude-alert-kubernetes-analyzer` image in your cluster
2. Set the required environment variables (`WEBHOOK_SECRET`, `API_KEY`)
3. Configure `PROMETHEUS_URL` if your Prometheus isn't at the default address
4. Add a webhook receiver to your Alertmanager config pointing to the analyzer's `/webhook` endpoint with the matching bearer token

### CheckMK Analyzer

#### 1. Deploy the analyzer

Deploy the `claude-alert-checkmk-analyzer` image with:
- Required env vars: `WEBHOOK_SECRET`, `API_KEY`, `CHECKMK_API_USER`, `CHECKMK_API_SECRET`
- SSH private key mounted at `/ssh/id_ed25519`
- SSH `known_hosts` file mounted at `/ssh/known_hosts`

#### 2. Install the notification script

The notification script at `scripts/claude-analyzer-notify.sh` bridges CheckMK notifications to the analyzer webhook.

```bash
cp scripts/claude-analyzer-notify.sh \
  /omd/sites/<site>/local/share/check_mk/notifications/
chmod +x /omd/sites/<site>/local/share/check_mk/notifications/claude-analyzer-notify.sh
```

For Kubernetes deployments, the script can be deployed as a ConfigMap volume mount.

#### 3. Create a notification rule in CheckMK

1. Go to **Setup > Notifications > Add rule**
2. Notification method: **Custom script** `claude-analyzer-notify.sh`
3. Parameter 1: Webhook URL (default: `http://claude-checkmk-analyzer.monitoring:8080/webhook`)
4. Parameter 2: Webhook secret (must match `WEBHOOK_SECRET`)
5. **Enable "Recovery" as a notification event** — this is required for cooldown deduplication to work correctly.

The script sends host/service alert data as JSON to the webhook. Exit codes: `0` = success, `1` = 503/queue full (CheckMK will retry), `2` = error.

> **Why Recovery notifications are required:** When a service fires, a cooldown is set to prevent duplicate analysis. If the service recovers and then fails again within the cooldown window, the second failure would be silently suppressed without a Recovery notification to clear the cooldown. Enabling Recovery ensures that any subsequent PROBLEM after a recovery is analyzed immediately.

### Host Context via Custom Attributes

The checkmk-analyzer can inject operator-provided host notes into the analysis prompt, giving Claude host-specific context (OS, config paths, operational hints) before it starts investigating. This saves SSH rounds that would otherwise be spent discovering basics.

**Setup in CheckMK:**

1. Go to **Setup > Custom host attributes > Create new attribute**
2. Name: `ai_context`, Tpoc: Custom attributes, Data type: Simple Text, Help text (example): Information beeing send to claude analyzer
3. Mark "Show in host tables"
3. Save

**Example value:**
```
Debian 12, Nginx reverse proxy. Config: /etc/nginx/sites-enabled/. On disk-alerts first check /var/log/nginx.
```

When the attribute is set, it appears as a "Host Context (operator-provided)" section in the Claude prompt, before alert details and service list. Hosts without the attribute work exactly as before — no section is added.

The content is sanitized (control characters stripped, trimmed, truncated at 2 KB).

### SSH Diagnostic Commands

The checkmk-analyzer uses an **agentic approach**: Claude autonomously decides which commands to run on the alerted host via SSH, based on the alert context and previous command outputs. This replaces a static command list with a dynamic investigation loop (max 10 rounds).

**Allowed:** Any read-only diagnostic command (e.g. `df`, `free`, `top`, `ps`, `journalctl`, `cat`/`tail`/`head` on log files, `ss`, `ip`, `du`, `lsblk`, `lsof`, `find`, `systemctl status/show`, etc.)

**Denied (denylist):** Destructive or state-modifying commands are blocked by default: `rm`, `dd`, `mkfs`, `shutdown`, `reboot`, `sudo`, `su`, `chmod`, `chown`, `kill`, `mv`, `cp`, `mount`, `iptables`, `passwd`, `crontab`, `systemctl start/stop/restart`, and similar. The denylist is configurable via `SSH_DENIED_COMMANDS`. Set to empty to remove all guardrails.

Output is redacted (secrets removed) and truncated per command before being sent to Claude.

## Security

### Both Analyzers

- Non-root execution (UID 65534)
- Read-only root filesystem
- All Linux capabilities dropped
- Webhook auth is fail-closed (missing/invalid token = rejected)
- All diagnostic output passes through secret redaction before being sent to Claude (passwords, tokens, API keys, PEM blocks, emails)
- Claude API response tokens capped at 2048

### CheckMK Analyzer (additional)

- **Host validation**: Both `hostname` and `host_address` from the alert must match a known CheckMK host before any SSH connection is attempted
- **Strict SSH**: `known_hosts` from ConfigMap (no TOFU), key mounted as volume (not env var), no ForwardAgent
- **Command denylist**: Destructive/privileged commands blocked (defense-in-depth alongside unprivileged SSH user)
- **No shell**: Commands executed via SSH exec (argv), not through a shell
- **No privilege escalation**: SSH user has unprivileged access only; no `sudo`, `su`, `dmesg`, or `pkexec`

## Building

### Local

```bash
CGO_ENABLED=0 go build -o k8s-analyzer ./cmd/k8s-analyzer/
CGO_ENABLED=0 go build -o checkmk-analyzer ./cmd/checkmk-analyzer/
```

### Docker

```bash
docker build --target k8s-analyzer -t claude-alert-kubernetes-analyzer .
docker build --target checkmk-analyzer -t claude-alert-checkmk-analyzer .
```

### Testing

```bash
go test ./...
```

## Observability

Both analyzers expose a `/metrics` endpoint in Prometheus text format (no authentication required). The endpoint contains two sections:

**Operational counters** (unlabeled, always present):

| Metric | Type | Description |
|--------|------|-------------|
| `alert_analyzer_webhooks_received_total` | counter | Total webhook requests received |
| `alert_analyzer_alerts_queued_total` | counter | Alerts successfully enqueued for processing |
| `alert_analyzer_alerts_queue_full_total` | counter | Alerts dropped because the work queue was full |
| `alert_analyzer_alerts_cooldown_total` | counter | Alerts skipped because a duplicate is in cooldown |
| `alert_analyzer_alerts_processed_total` | counter | Alerts successfully analyzed and published |
| `alert_analyzer_alerts_failed_total` | counter | Alerts where analysis or publishing failed |
| `alert_analyzer_processing_duration_seconds` | summary | Processing time per alert (sum + count) |

**Labeled Prometheus metrics** (with `source` and/or `severity` labels):

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `alerts_analyzed_total` | counter | `source`, `severity` | Total alerts successfully analyzed |
| `alerts_cooldown_total` | counter | `source` | Alerts skipped due to active cooldown |
| `queue_depth` | gauge | `source` | Current number of alerts waiting in the work queue |
| `claude_api_duration_seconds` | histogram | — | Claude API call latency |
| `claude_api_errors_total` | counter | `source` | Claude API errors |
| `ntfy_publish_errors_total` | counter | `source` | ntfy publish failures |

The `source` label is `k8s` for the Kubernetes analyzer and `checkmk` for the CheckMK analyzer.

**Example Prometheus scrape config:**

```yaml
- job_name: claude-alert-analyzer
  static_configs:
    - targets: ['claude-alert-analyzer.monitoring:9101']
```

## CI/CD

GitHub Actions (`.github/workflows/build.yaml`) builds and pushes both images on push to `main` when relevant files change (`cmd/`, `internal/`, `Dockerfile`, `go.mod`, `go.sum`).

Images are tagged with both the short commit SHA and `latest`:

- `ghcr.io/madic-creates/claude-alert-kubernetes-analyzer:{sha,latest}`
- `ghcr.io/madic-creates/claude-alert-checkmk-analyzer:{sha,latest}`
