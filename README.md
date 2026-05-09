# Claude Alert Analyzer

<a href="docs/screenshot01.png"><img src="docs/screenshot01.png" alt="Analyzer Result" height="400" align="left" hspace="20"></a>

LLM-powered root-cause analysis for monitoring alerts. Incoming alerts from Alertmanager (Kubernetes) or CheckMK trigger automated diagnostic collection, which is sent to Claude for analysis. The resulting root-cause assessment is delivered to operators via [ntfy](https://ntfy.sh).

Instead of staring at a 3 AM "DiskPressure" alert and manually running ten `kubectl` / `ssh` commands, you get a short markdown summary on your phone: likely cause, blast radius, suggested remediation — derived from real metrics, events, pod logs, and (for CheckMK hosts) live SSH diagnostics.

<br clear="left">

## Blog posts (German)

- [KI-gestützte Alert-Analyse für Kubernetes und CheckMK](https://www.geekbundle.org/ki-gestuetzte-alert-analyse-fuer-kubernetes-und-checkmk/)
- [Claude Analyzer — Entwicklung](https://www.geekbundle.org/claude-analyzer-entwicklung/)

## How it works

```
Alert fires → Webhook → Gather diagnostics → Claude / LLM API → ntfy notification
```

Two independent analyzers share a common library but run as separate binaries:

| Analyzer | Alert Source | Diagnostics Gathered |
|----------|-------------|---------------------|
| **k8s-analyzer** | Alertmanager webhook | Prometheus metrics, K8s events, pod status, pod logs + agentic `kubectl_exec` / `promql_query` loop |
| **checkmk-analyzer** | CheckMK notification script | CheckMK REST API (host/service state), agentic SSH diagnostics |

Both deduplicate repeat alerts (configurable cooldown) and process work concurrently (5 workers, queue depth 20). All diagnostic output is passed through a secret-redaction filter before leaving the analyzer.

## Quick start (Docker — CheckMK)

The fastest way to try the **checkmk-analyzer**. For Kubernetes, see [`docs/install-k8s.md`](docs/install-k8s.md).

You need:

- An [Anthropic API key](https://console.anthropic.com/) or compatible token
- An [ntfy](https://ntfy.sh) server
- SSH key + `known_hosts` for the monitored hosts (unprivileged user)
- A CheckMK automation user

```bash
mkdir -p ./ssh
cp /path/to/id_ed25519  ./ssh/id_ed25519
cp /path/to/known_hosts ./ssh/known_hosts
chmod 600 ./ssh/id_ed25519

docker run -d --name checkmk-analyzer \
  --restart unless-stopped --read-only --cap-drop ALL --user 65534:65534 \
  -p 127.0.0.1:8080:8080 -p 127.0.0.1:9101:9101 \
  -v "$(pwd)/ssh:/ssh:ro" \
  -e WEBHOOK_SECRET="change-me" \
  -e ANTHROPIC_API_KEY="sk-ant-..." \
  -e CHECKMK_API_URL="https://checkmk.example.com/mysite/check_mk/api/1.0/" \
  -e CHECKMK_API_USER="automation" \
  -e CHECKMK_API_SECRET="..." \
  -e NTFY_PUBLISH_URL="https://ntfy.example.com" \
  -e NTFY_PUBLISH_TOPIC="checkmk-analysis" \
  ghcr.io/madic-creates/claude-alert-checkmk-analyzer:latest

curl -sf http://127.0.0.1:8080/health
```

Then install the CheckMK notification script and create a notification rule — full steps in [`docs/install-checkmk.md`](docs/install-checkmk.md).

## Container images

Pre-built images are published to GHCR on every push to `main`:

```
ghcr.io/madic-creates/claude-alert-kubernetes-analyzer:latest
ghcr.io/madic-creates/claude-alert-checkmk-analyzer:latest
```

| Image | Base | Size |
|-------|------|------|
| `claude-alert-kubernetes-analyzer` | `scratch` | ~20 MB |
| `claude-alert-checkmk-analyzer` | `alpine:3.23` | ~60 MB (includes `openssh-client`) |

## Documentation

**Install**

- [`docs/install-k8s.md`](docs/install-k8s.md) — Kubernetes deployment (Kustomize manifests, Alertmanager wiring, RBAC)
- [`docs/install-checkmk.md`](docs/install-checkmk.md) — CheckMK deployment (Docker / Compose, notification script, rules, optional `ai_context` host attribute)

**Operations**

- [`docs/configuration.md`](docs/configuration.md) — full env-var reference (shared, k8s, checkmk, LLM provider, storm robustness)
- [`docs/observability.md`](docs/observability.md) — API endpoints, Prometheus metrics, scrape config, logging
- [`docs/hardening.md`](docs/hardening.md) — runtime hardening, agentic-loop guardrails, RBAC and SSH details
- [`docs/cost-and-storm-protection.md`](docs/cost-and-storm-protection.md) — operator guide for prompt caching, severity-based routing, token-cost dashboards, storm-mode and circuit-breaker rollout

**Development & maintenance**

- [`docs/development.md`](docs/development.md) — build, test, project layout, key patterns, CI/CD
- [`docs/cost-and-storm-protection-internals.md`](docs/cost-and-storm-protection-internals.md) — architecture and component reference for the cost/storm features
- [`docs/pre-commit.md`](docs/pre-commit.md) — pre-commit hook configuration
- [`docs/renovate.md`](docs/renovate.md) — dependency update automation
- [`docs/cleanup-ghcr.md`](docs/cleanup-ghcr.md) — GHCR tag retention

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See [`NOTICE`](NOTICE) for attribution of bundled third-party software.
