# Installation — CheckMK Analyzer

End-to-end install for the **checkmk-analyzer**. Receives CheckMK notification webhooks, queries the CheckMK REST API, and (optionally) runs an agentic SSH diagnostic loop on the affected host.

## Prerequisites

- A CheckMK instance with an automation user
- SSH access to monitored hosts (unprivileged account; the analyzer also enforces a command denylist on top)
- An [Anthropic API key](https://console.anthropic.com/) (`ANTHROPIC_API_KEY`) **or** an OpenRouter / compatible-provider token (`ANTHROPIC_AUTH_TOKEN`) — exactly one of the two
- An [ntfy](https://ntfy.sh) server for receiving analysis results

## Container image

```
ghcr.io/madic-creates/claude-alert-checkmk-analyzer:latest
```

## 1. Deploy the analyzer

Required env vars: `WEBHOOK_SECRET`, `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN`, `CHECKMK_API_USER`, `CHECKMK_API_SECRET`. SSH private key mounted at `/ssh/id_ed25519`, `known_hosts` at `/ssh/known_hosts` (strict host checking — no TOFU).

The SSH user (`SSH_USER`, default `nagios`) must be an **unprivileged** account. The analyzer enforces a command denylist on top of that as defense in depth.

### Example — plain Docker

```bash
# Prepare SSH material (private key + known_hosts) in a local directory
mkdir -p ./ssh
cp /path/to/id_ed25519  ./ssh/id_ed25519
cp /path/to/known_hosts ./ssh/known_hosts
chmod 600 ./ssh/id_ed25519

docker run -d \
  --name checkmk-analyzer \
  --restart unless-stopped \
  --read-only \
  --cap-drop ALL \
  --user 65534:65534 \
  -p 127.0.0.1:8080:8080 \
  -p 127.0.0.1:9101:9101 \
  -v "$(pwd)/ssh:/ssh:ro" \
  -e WEBHOOK_SECRET="change-me" \
  -e ANTHROPIC_API_KEY="sk-ant-..." \
  -e CHECKMK_API_URL="https://checkmk.example.com/mysite/check_mk/api/1.0/" \
  -e CHECKMK_API_USER="automation" \
  -e CHECKMK_API_SECRET="..." \
  -e NTFY_PUBLISH_URL="https://ntfy.example.com" \
  -e NTFY_PUBLISH_TOPIC="checkmk-analysis" \
  ghcr.io/madic-creates/claude-alert-checkmk-analyzer:latest

# Tail logs
docker logs -f checkmk-analyzer

# Smoke-test the health endpoint
curl -sf http://127.0.0.1:8080/health
```

### Example — Docker Compose

```yaml
services:
  checkmk-analyzer:
    image: ghcr.io/madic-creates/claude-alert-checkmk-analyzer:latest
    restart: unless-stopped
    read_only: true
    cap_drop: [ALL]
    user: "65534:65534"
    ports:
      - "127.0.0.1:8080:8080"
      - "127.0.0.1:9101:9101"
    volumes:
      - ./ssh:/ssh:ro
    environment:
      WEBHOOK_SECRET: "change-me"
      ANTHROPIC_API_KEY: "sk-ant-..."
      CHECKMK_API_URL: "https://checkmk.example.com/mysite/check_mk/api/1.0/"
      CHECKMK_API_USER: "automation"
      CHECKMK_API_SECRET: "..."
      NTFY_PUBLISH_URL: "https://ntfy.example.com"
      NTFY_PUBLISH_TOPIC: "checkmk-analysis"
```

Start with `docker compose up -d`. See [`configuration.md`](configuration.md) for the full environment-variable reference.

## 2. Install the notification script

The script at [`deploy/scripts/claude-analyzer-notify.sh`](../deploy/scripts/claude-analyzer-notify.sh) bridges CheckMK notifications to the analyzer webhook:

```bash
cp deploy/scripts/claude-analyzer-notify.sh \
  /omd/sites/<site>/local/share/check_mk/notifications/
chmod +x /omd/sites/<site>/local/share/check_mk/notifications/claude-analyzer-notify.sh
```

For containerized CheckMK deployments, mount the script via a ConfigMap.

## 3. Create a notification rule in CheckMK

1. Go to **Setup > Notifications > Add rule**
2. Notification method: **Custom script** `claude-analyzer-notify.sh`
3. Parameter 1: Webhook URL (default: `http://claude-checkmk-analyzer.monitoring:8080/webhook`)
4. Parameter 2: Webhook secret (must match `WEBHOOK_SECRET`)
5. **Enable "Recovery" as a notification event** — required for cooldown deduplication to work correctly.

Script exit codes: `0` = success, `1` = 503/queue full (CheckMK will retry), `2` = fatal error.

> **Why Recovery notifications are required:** When a service fires, a cooldown prevents duplicate analysis. If the service recovers and fails again inside the cooldown window, the second failure would be silently suppressed without a Recovery notification to clear the cooldown. Enabling Recovery ensures any subsequent PROBLEM after a recovery is analyzed immediately.

## 4. (Optional) Host context via custom attribute

The checkmk-analyzer can inject operator-provided host notes into the Claude prompt, giving the model host-specific context (OS, config paths, operational hints) before it starts investigating. This saves SSH rounds spent discovering basics.

Setup in CheckMK:

1. **Setup > Custom host attributes > Create new attribute**
2. Name: `ai_context`, Topic: Custom attributes, Data type: Simple Text
3. Tick "Show in host tables"

Example value:

```
Debian 12, Nginx reverse proxy. Config: /etc/nginx/sites-enabled/. On disk-alerts first check /var/log/nginx.
```

When set, the attribute appears as a "Host Context (operator-provided)" section in the prompt, before alert details. Content is sanitized (control chars stripped, trimmed, truncated at 2 KB). Hosts without the attribute behave exactly as before.

## Next steps

- [`configuration.md`](configuration.md) — full env-var reference (shared + checkmk-specific)
- [`observability.md`](observability.md) — metrics, scrape config, logging
- [`security.md`](security.md) — SSH hardening, command denylist, host validation
- [`cost-and-storm-protection.md`](cost-and-storm-protection.md) — prompt caching, severity routing, storm-mode, circuit-breaker
