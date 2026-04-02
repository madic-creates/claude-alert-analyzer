# Claude Alert Analyzer

A Go multi-binary repository providing LLM-powered alert analysis for both Kubernetes (Alertmanager) and CheckMK (Nagios-based) monitoring systems. Each analyzer receives alerts via webhooks, gathers diagnostic context from its respective monitoring stack, sends everything to Claude for root-cause analysis, and publishes results to ntfy.

## Architecture

```
                        ┌─────────────────────────────────────────┐
                        │         claude-alert-analyzer repo       │
                        │                                         │
                        │  internal/shared/                       │
                        │    claude.go   ntfy.go   cooldown.go    │
                        │    redact.go   types.go                 │
                        │                                         │
                        │  internal/k8s/          internal/checkmk│
                        │    context.go             context.go    │
                        │    handler.go             handler.go    │
                        │    types.go               ssh.go        │
                        │                           types.go      │
                        │                                         │
                        │  cmd/k8s-analyzer/   cmd/checkmk-analyzer│
                        │    main.go              main.go         │
                        └─────────────────────────────────────────┘
```

### K8s Analyzer

```
Alertmanager → POST /webhook → Gather context → Claude API → ntfy
                                  ├── Prometheus metrics
                                  ├── K8s events
                                  ├── Pod status
                                  └── Pod logs (allowlisted namespaces)
```

### CheckMK Analyzer

```
CheckMK Notification Script → POST /webhook → Gather context → Claude API → ntfy
                                                 ├── CheckMK REST API (host/service details)
                                                 └── SSH diagnostics (logs, system info)
```

## Binaries

| Binary | Base Image | Description |
|--------|-----------|-------------|
| `k8s-analyzer` | scratch (~13MB) | Kubernetes alert analysis via Alertmanager webhooks |
| `checkmk-analyzer` | Alpine (~25MB) | CheckMK alert analysis via custom notification script, includes openssh-client |

## API Endpoints

Both binaries expose the same endpoints:

- `GET /health` -- liveness/readiness probe
- `POST /webhook` -- alert receiver (requires `Authorization: Bearer <WEBHOOK_SECRET>`)

## Configuration

### Shared Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WEBHOOK_SECRET` | (required) | Shared secret for webhook authentication |
| `API_KEY` | (required) | API key for Claude (Anthropic or OpenRouter) |
| `API_BASE_URL` | `https://api.anthropic.com/v1/messages` | LLM API endpoint |
| `CLAUDE_MODEL` | `claude-sonnet-4-6` | Model name |
| `PORT` | `8080` | HTTP server port |
| `COOLDOWN_SECONDS` | `300` | Per-alert cooldown |
| `NTFY_PUBLISH_URL` | `https://ntfy.geekbundle.org` | ntfy server URL |
| `NTFY_PUBLISH_TOPIC` | varies | ntfy topic |
| `NTFY_PUBLISH_TOKEN` | (empty) | ntfy auth token |

### K8s Analyzer Specific

| Variable | Default | Description |
|----------|---------|-------------|
| `PROMETHEUS_URL` | `http://kube-prometheus-stack-prometheus.monitoring.svc.cluster.local:9090` | Prometheus endpoint |
| `ALLOWED_NAMESPACES` | `monitoring,databases,media` | Namespace allowlist for pod log collection |
| `MAX_LOG_BYTES` | `2048` | Per-pod log truncation limit |
| `SKIP_RESOLVED` | `true` | Skip resolved alerts |
| `NTFY_PUBLISH_TOPIC` | `kubernetes-analysis` | Default topic |

### CheckMK Analyzer Specific

| Variable | Default | Description |
|----------|---------|-------------|
| `CHECKMK_API_URL` | `http://checkmk-service.monitoring:5000/cmk/check_mk/api/1.0/` | CheckMK REST API URL |
| `CHECKMK_API_USER` | (required) | CheckMK automation user |
| `CHECKMK_API_SECRET` | (required) | CheckMK automation secret |
| `SSH_USER` | `nagios` | SSH user for host diagnostics |
| `SSH_KEY_PATH` | `/ssh/id_ed25519` | Path to SSH private key |
| `SSH_KNOWN_HOSTS_PATH` | `/ssh/known_hosts` | Path to known_hosts file |
| `NTFY_PUBLISH_TOPIC` | `checkmk-analysis` | Default topic |

### Provider-Specific Authentication

The Claude client detects the provider from `API_BASE_URL`:

- URL contains `anthropic.com`: uses `x-api-key` header + `anthropic-version` header
- All other URLs (OpenRouter, etc.): uses `Authorization: Bearer` header

## Security

### Both Analyzers

- Runs as non-root (UID 65534)
- Read-only root filesystem
- All capabilities dropped
- Webhook authentication required (fail-closed)
- Secrets redacted from all output before sending to Claude (passwords, tokens, keys, PEM blocks, emails)
- Output truncated to prevent excessive token usage

### CheckMK Analyzer Additional

- SSH host validation: `hostname` AND `host_address` must match a known CheckMK host before SSH connection is attempted
- SSH `known_hosts` from ConfigMap (no Trust-On-First-Use)
- SSH key mounted as volume (not as env var, no ForwardAgent)
- Command allowlist: only predefined diagnostic commands are executed
- Service names validated against `^[a-zA-Z0-9_@.-]+$` to prevent injection
- Commands executed via SSH exec (argv form), not via shell
- No root/sudo: the SSH user has only unprivileged rights. The analyzer never attempts `sudo`, `su`, `dmesg`, `pkexec`, or any privilege escalation

### SSH Diagnostic Commands

Commands are selected based on alert category (heuristically detected from service description):

| Category | Commands |
|----------|----------|
| Always | `journalctl --no-pager -p err -n 50 --since 1 hour ago` |
| CPU/Load | `top -bn1 -o %CPU` (20 lines), `uptime` |
| Disk | `df -h` |
| Memory | `free -h`, `ps aux --sort=-%mem` (10 lines) |
| Service | `systemctl status <svc>`, `journalctl --no-pager -u <svc> -n 30` |

Output truncation (replacing shell pipes) is done Go-side after reading the full output.

## Building

### Local

```bash
go build ./cmd/k8s-analyzer/
go build ./cmd/checkmk-analyzer/
```

### Docker

```bash
# K8s analyzer (scratch image)
docker build --target k8s-analyzer -t claude-alert-kubernetes-analyzer .

# CheckMK analyzer (Alpine image with SSH)
docker build --target checkmk-analyzer -t claude-alert-checkmk-analyzer .
```

## Testing

```bash
go test ./...
```

## CI/CD

GitHub Actions builds both images on push to `main`:

- `ghcr.io/madic-creates/claude-alert-kubernetes-analyzer:<sha>` (K8s)
- `ghcr.io/madic-creates/claude-alert-checkmk-analyzer:<sha>` (CheckMK)

## CheckMK Notification Script

The CheckMK notification script is included at `scripts/claude-analyzer-notify.sh`. Install it into CheckMK:

```bash
# Copy to CheckMK notifications directory
cp scripts/claude-analyzer-notify.sh \
  /omd/sites/<site>/local/share/check_mk/notifications/
chmod +x /omd/sites/<site>/local/share/check_mk/notifications/claude-analyzer-notify.sh
```

Then create a notification rule in CheckMK:
1. Go to Setup > Notifications > Add rule
2. Notification method: Custom script `claude-analyzer-notify.sh`
3. Parameter 1: Webhook URL (default: `http://claude-checkmk-analyzer.monitoring:8080/webhook`)
4. Parameter 2: Webhook secret (must match `WEBHOOK_SECRET` in the analyzer deployment)

For Kubernetes deployments, the script can be deployed as a ConfigMap volume mount.
