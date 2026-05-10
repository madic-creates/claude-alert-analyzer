# Installation — Kubernetes Analyzer

End-to-end install for the **k8s-analyzer**. Receives Alertmanager webhooks and runs in-cluster only (`rest.InClusterConfig()` — must therefore be deployed inside the cluster it is analyzing).

## Prerequisites

- A Kubernetes cluster with Alertmanager
- An [Anthropic API key](https://console.anthropic.com/) (`ANTHROPIC_API_KEY`) **or** an OpenRouter / compatible-provider token (`ANTHROPIC_AUTH_TOKEN`) — exactly one of the two
- An [ntfy](https://ntfy.sh) server for receiving analysis results

## Container image

```
ghcr.io/madic-creates/claude-alert-kubernetes-analyzer:latest
```

## 1. Deploy the analyzer

Minimum required environment variables:

- `WEBHOOK_SECRET` — bearer token that Alertmanager must present
- `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN`
- `PROMETHEUS_URL` — only if your Prometheus isn't at the default address

The analyzer needs read access to cluster resources (events, pods, pod logs) — bind it to a ServiceAccount with a read-only ClusterRole. The agent enforces a verb allowlist (read-only built-ins only) and rejects identity-overriding flags before invoking `kubectl`, but RBAC is the authoritative gate — exclude `secrets` from the role to keep credentials out of reach.

Example manifests (Deployment, ServiceAccount + RBAC, Service, Secret template, Kustomization) live in [`deploy/k8s-analyzer/`](../deploy/k8s-analyzer/). To deploy:

```bash
# 1. Fill in secrets
cp deploy/k8s-analyzer/secret.example.yaml deploy/k8s-analyzer/secret.yaml
$EDITOR deploy/k8s-analyzer/secret.yaml
# then uncomment `- secret.yaml` in deploy/k8s-analyzer/kustomization.yaml

# 2. Apply
kubectl apply -k deploy/k8s-analyzer/
```

The manifests target namespace `monitoring` and apply the same hardening as the Docker image (non-root UID 65534, read-only root FS, all capabilities dropped, `RuntimeDefault` seccomp). Review them before applying — in particular `PROMETHEUS_URL`, `MAX_AGENT_ROUNDS`, and resource limits.

## 2. Configure Alertmanager

Add a webhook receiver pointing at the analyzer's `/webhook` endpoint with the matching bearer token. The `group_*` and `repeat_interval` settings on the route are the first line of defense against re-analyzing the same alert — pick a `repeat_interval` long enough that a still-firing alert doesn't trigger a fresh analysis on every Alertmanager re-send. The analyzer's own `COOLDOWN_SECONDS` (see [`configuration.md`](configuration.md)) acts as a second line of defense in case Alertmanager fires more often than expected.

```yaml
routes:
  - receiver: claude-analyzer
    matchers:
      - severity =~ "warning|critical"
    continue: true
    # Dedup tuning — avoid re-analyzing the same firing alert.
    group_by: ['alertname', 'namespace']
    group_wait: 30s
    group_interval: 5m
    repeat_interval: 12h
  - receiver: claude-analyzer
    matchers:
      - alertname = "CPUThrottlingHigh"
    group_by: ['alertname', 'namespace']
    group_wait: 30s
    group_interval: 5m
    repeat_interval: 12h
receivers:
  - name: claude-analyzer
    webhook_configs:
      - url: http://claude-k8s-analyzer.monitoring:8080/webhook
        http_config:
          authorization:
            type: Bearer
            credentials: <WEBHOOK_SECRET>
```

### Variant: notify a chat sink frequently, analyze rarely

A common setup is to fan an alert out to two sinks — e.g. ntfy (or Slack) for human notification, plus the analyzer for root-cause analysis. If both webhooks live in the **same** receiver, they share the route's `repeat_interval` and you can't decouple their cadence. Split them into **separate receivers** behind **separate routes** so the analyzer can run on a longer cycle while the chat sink keeps its short one.

```yaml
route:
  group_by: [namespace]
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 1h          # chat sink fires hourly while alert is firing
  receiver: ntfy
  routes:
    # Analyzer with its own (longer) cadence; falls through to root → ntfy.
    - receiver: claude-analyzer
      matchers:
        - severity =~ "warning|critical"
      group_by: ['alertname', 'namespace']  # finer grouping → per-alert dedup
      group_wait: 30s
      group_interval: 5m
      repeat_interval: 12h                  # analyzer only re-fires every 12h
      continue: true                        # ensure ntfy still receives the alert

receivers:
  - name: claude-analyzer
    webhook_configs:
      - url: http://claude-k8s-analyzer.monitoring:8080/webhook
        send_resolved: false
        http_config:
          authorization:
            type: Bearer
            credentials: <WEBHOOK_SECRET>
  - name: ntfy
    webhook_configs:
      - url: <NTFY_WEBHOOK_URL>
        http_config:
          basic_auth: { username: <user>, password: <pass> }
```

Key points:

- `continue: true` on the analyzer sub-route is mandatory — without it, matching alerts stop at the analyzer route and never reach ntfy.
- The sub-route's `group_by` overrides the root's, giving the analyzer its own group state and an independent `repeat_interval` timer.
- Keep route ordering intact: any `null`-receiver entries (e.g. `InfoInhibitor`) must remain **before** the analyzer route so they aren't sent for analysis.
- Pair this with `COOLDOWN_SECONDS` in the analyzer (e.g. `43200` for 12h) as a second line of defense in case the Alertmanager config drifts.

## Next steps

- [`configuration.md`](configuration.md) — full env-var reference (shared + k8s-specific)
- [`observability.md`](observability.md) — metrics, scrape config, logging
- [`hardening.md`](hardening.md) — runtime hardening, RBAC, agentic-loop guardrails
- [`cost-and-storm-protection.md`](cost-and-storm-protection.md) — prompt caching, severity routing, storm-mode, circuit-breaker
