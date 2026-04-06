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

Both analyzers expose:

- `GET /health` -- liveness/readiness probe (returns `200 ok`)
- `POST /webhook` -- alert receiver (requires `Authorization: Bearer <WEBHOOK_SECRET>`)

## Configuration

### Shared Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WEBHOOK_SECRET` | **(required)** | Bearer token for webhook authentication |
| `API_KEY` | **(required)** | Anthropic or OpenRouter API key |
| `API_BASE_URL` | `https://api.anthropic.com/v1/messages` | LLM API endpoint |
| `CLAUDE_MODEL` | `claude-sonnet-4-6` | Model to use for analysis |
| `PORT` | `8080` | HTTP listen port |
| `COOLDOWN_SECONDS` | `300` | Seconds before re-analyzing the same alert |
| `NTFY_PUBLISH_URL` | `https://ntfy.example.com` | ntfy server URL |
| `NTFY_PUBLISH_TOPIC` | *(varies per analyzer)* | ntfy topic name |
| `NTFY_PUBLISH_TOKEN` | *(empty)* | ntfy auth token (optional) |

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
| `SSH_USER` | `nagios` | SSH user for host diagnostics |
| `SSH_KEY_PATH` | `/ssh/id_ed25519` | Path to SSH private key |
| `SSH_KNOWN_HOSTS_PATH` | `/ssh/known_hosts` | Path to known_hosts file |
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

The script sends host/service alert data as JSON to the webhook. Exit codes: `0` = success, `1` = 503/queue full (CheckMK will retry), `2` = error.

### SSH Diagnostic Commands

The checkmk-analyzer connects to the alerted host via SSH and runs diagnostic commands based on the alert category (heuristically detected from the service description):

| Category | Keywords | Commands |
|----------|----------|----------|
| Always | -- | `journalctl --no-pager -p err -n 50 --since "1 hour ago"` |
| CPU/Load | cpu, load | `top -bn1 -o %CPU` (first 20 lines), `uptime` |
| Disk | disk, filesystem, mount | `df -h` |
| Memory | memory, swap, mem | `free -h`, `ps aux --sort=-%mem` (first 10 lines) |
| Service | systemd, service, process | `systemctl status <svc>`, `journalctl --no-pager -u <svc> -n 30` |

Output is truncated Go-side after reading the full response (no shell pipes).

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
- **Command allowlist**: Only the predefined diagnostic commands above are executed
- **Input validation**: Service names validated against `^[a-zA-Z0-9_@.\-]+$` (max 128 chars)
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

## CI/CD

GitHub Actions (`.github/workflows/build.yaml`) builds and pushes both images on push to `main` when relevant files change (`cmd/`, `internal/`, `Dockerfile`, `go.mod`, `go.sum`).

Images are tagged with both the short commit SHA and `latest`:

- `ghcr.io/madic-creates/claude-alert-kubernetes-analyzer:{sha,latest}`
- `ghcr.io/madic-creates/claude-alert-checkmk-analyzer:{sha,latest}`
