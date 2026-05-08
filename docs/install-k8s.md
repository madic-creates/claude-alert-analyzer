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

Add a webhook receiver pointing at the analyzer's `/webhook` endpoint with the matching bearer token:

```yaml
routes:
  - receiver: claude-analyzer
    matchers:
      - severity =~ "warning|critical"
    continue: true
  - receiver: claude-analyzer
    matchers:
      - alertname = "CPUThrottlingHigh"
receivers:
  - name: claude-analyzer
    webhook_configs:
      - url: http://claude-k8s-analyzer.monitoring:8080/webhook
        http_config:
          authorization:
            type: Bearer
            credentials: <WEBHOOK_SECRET>
```

## Next steps

- [`configuration.md`](configuration.md) — full env-var reference (shared + k8s-specific)
- [`observability.md`](observability.md) — metrics, scrape config, logging
- [`security.md`](security.md) — hardening, RBAC, agentic-loop guardrails
- [`cost-and-storm-protection.md`](cost-and-storm-protection.md) — prompt caching, severity routing, storm-mode, circuit-breaker
