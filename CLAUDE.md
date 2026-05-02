# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Two independent alert analyzer services that receive monitoring webhooks, gather diagnostic context, send the context to the Claude API for root-cause analysis, and publish the analysis to ntfy. Both share a common library but are separate binaries with separate Dockerfile targets.

- **k8s-analyzer** — Receives Alertmanager webhooks, runs static prefetch (Prometheus metrics + Kubernetes events/pods/logs) plus an agentic Claude tool-loop (`kubectl_exec`, `promql_query`) for root-cause analysis.
- **checkmk-analyzer** — Receives CheckMK notification webhooks, gathers CheckMK host services + SSH diagnostics, analyzes via Claude API

## Build & Test

Go 1.26+, no CGO dependencies.

```bash
# Build both binaries
CGO_ENABLED=0 go build -o k8s-analyzer ./cmd/k8s-analyzer/
CGO_ENABLED=0 go build -o checkmk-analyzer ./cmd/checkmk-analyzer/

# Run all tests
go test ./...

# Run tests for a specific package
go test ./internal/shared/
go test ./internal/checkmk/

# Docker multi-stage build (two targets)
docker build --target k8s-analyzer -t k8s-analyzer .
docker build --target checkmk-analyzer -t checkmk-analyzer .
```

## Architecture

### Processing Pipeline (same for both analyzers)

```
Webhook → Auth check → Cooldown dedup → Work queue (buffered chan, 5 workers)
  → Context gathering (parallel) → Claude API analysis → ntfy publish
```

### Package Layout

- `internal/shared/` — Common types (`AlertPayload`, `BaseConfig`, `AnalysisContext`), Claude API client (plain `Analyze` + multi-turn `RunToolLoop`), `Analyzer`/`ToolLoopRunner` interfaces, ntfy publisher, cooldown manager, secret redaction, shared HTTP server + worker pool (`Server` in `server.go`), operational counters (`AlertMetrics`) and labeled Prometheus metrics (`PrometheusMetrics`) exposed at `/metrics` on a separate port
- `internal/k8s/` — Alertmanager webhook handler, Prometheus PromQL queries, Kubernetes context gathering (events, pod status, logs with namespace allowlist), `AlertPayloadToAlert` conversion (`convert.go`), `ProcessAlert` orchestration (`pipeline.go`)
- `internal/checkmk/` — CheckMK webhook handler, CheckMK REST API client, SSH diagnostic runner with alert category detection (CPU/disk/memory/service), agentic tool-loop runner (`RunAgenticDiagnostics` in `agent.go`), `ProcessAlert` orchestration (`pipeline.go`)
- `cmd/k8s-analyzer/` and `cmd/checkmk-analyzer/` — Entrypoints that load config, construct dependencies (Claude client, publishers, cooldown manager, metrics), and hand them to `shared.NewServer(...).Run(handler)` which owns the worker pool, HTTP servers, and graceful shutdown

### Key Design Patterns

- **Alert normalization**: Both sources convert to `shared.AlertPayload` with `Fields map[string]string` for source-specific data. k8s uses `label:` and `annotation:` prefixed keys.
- **Context gathering pattern**: Each analyzer exports a `GatherContext(...)` function that returns `shared.AnalysisContext` — a list of named sections rendered into the Claude prompt. Runs data collection concurrently (goroutines + channels); CheckMK gathers host services + SSH in parallel, k8s gathers Prometheus + kube context in parallel.
- **Agentic diagnostics (CheckMK)**: After static context gathering, `RunAgenticDiagnostics` drives a multi-turn Claude tool-use loop (via `ToolLoopRunner`) where Claude iteratively requests SSH commands on the affected host. Commands are validated against an allow/deny list with `denyReason` feedback; round budget capped by `MAX_AGENT_ROUNDS`.
- **Agentic diagnostics (k8s)**: After static context gathering, `RunAgenticDiagnostics` drives a multi-turn Claude tool-use loop (via `ToolLoopRunner`) where Claude iteratively requests `kubectl_exec` (argv-based subprocess) and `promql_query` calls. kubectl is invoked at a fixed path (`/usr/local/bin/kubectl`) with a scrubbed environment (only `HOME`/`USER`); a verb allowlist + global-flag denylist gate the call before subprocess invocation; RBAC is the authoritative server-side enforcement.
- **Cooldown dedup**: `CooldownManager` prevents re-analyzing the same alert within a configurable TTL. Cooldown is cleared on analysis failure so retries work.
- **Security**: All gathered output passes through `RedactSecrets()`. SSH commands use strict known_hosts and input validation. kubectl is invoked via argv at a fixed path with a scrubbed environment; RBAC is the authoritative enforcement layer.
- **API flexibility**: Claude API client always uses Anthropic Messages API format with `x-api-key` auth. Compatible alternative providers must accept `x-api-key` (e.g. via an auth-translating proxy).
- **Metrics**: Counters/gauges/histogram (`alerts_analyzed_total`, `alerts_cooldown_total`, `queue_depth`, `claude_api_duration_seconds`, `claude_api_errors_total`, `ntfy_publish_errors_total`, `claude_input_tokens_total`, `claude_output_tokens_total`, `claude_cache_creation_tokens_total`, `claude_cache_read_tokens_total`) live in a private Prometheus registry and are served on `METRICS_PORT` (separate from the webhook port).

## Environment Variables

Both analyzers require: `WEBHOOK_SECRET`, `API_KEY`
CheckMK additionally requires: `CHECKMK_API_USER`, `CHECKMK_API_SECRET`

Common optional: `PORT` (default `8080`), `METRICS_PORT` (default `9101`), `NTFY_PUBLISH_URL`, `NTFY_PUBLISH_TOPIC`, `NTFY_PUBLISH_TOKEN`, `CLAUDE_MODEL`, `API_BASE_URL`, `COOLDOWN_SECONDS`, `LOG_LEVEL`, `MAX_AGENT_ROUNDS` (default `10`, tool-loop budget). Severity-specific overrides for model and rounds are documented in the "Cost & Storm Protection" section below.
k8s optional: `MAX_LOG_BYTES`, `PROMETHEUS_URL`, `SKIP_RESOLVED`.

k8s-analyzer runs in-cluster only (`rest.InClusterConfig()`).

## Cost & Storm Protection (Phase 1)

The analyzers route Claude API calls based on alert severity to reduce cost. Defaults preserve current behavior — overrides are opt-in.

### Severity-based model routing

- `CLAUDE_MODEL_CRITICAL` (default: `$CLAUDE_MODEL`)
- `CLAUDE_MODEL_WARNING` (default: `$CLAUDE_MODEL`)
- `CLAUDE_MODEL_INFO` (default: `$CLAUDE_MODEL`)

Suggested setup: `critical` → Opus, `warning`/`info` → Haiku. Reduces cost ~12× for non-critical alerts.

### Severity-based agent rounds (range 0-50, optional)

- `MAX_AGENT_ROUNDS_CRITICAL` (default: `$MAX_AGENT_ROUNDS`)
- `MAX_AGENT_ROUNDS_WARNING` (default: `$MAX_AGENT_ROUNDS`)
- `MAX_AGENT_ROUNDS_INFO` (default: `$MAX_AGENT_ROUNDS`)

Special value `0` skips the tool-loop entirely and runs a static `Analyze` only — best for noisy info alerts. The static path uses pre-fetched context (Prometheus metrics, kube events, pod status, logs for k8s; host services + alert payload for checkmk) without giving Claude tools to call.

### Prompt caching

Enabled automatically. Anthropic prompt caching is applied at three breakpoints per request:

1. System prompt (last block) — cached across all alerts of the same source
2. Tool definitions (last tool) — cached across rounds within a tool-loop
3. Tool-loop conversation history (last `tool_result` per round) — sliding cache that pays off in multi-round analyses

Hit-rate is visible via Prometheus metrics:

- `claude_input_tokens_total{source,severity,model}`
- `claude_output_tokens_total{source,severity,model}`
- `claude_cache_creation_tokens_total{source,severity,model}`
- `claude_cache_read_tokens_total{source,severity,model}`

Anthropic only caches blocks larger than ~1024 tokens (Sonnet/Opus, ~2048 for Haiku). For small system prompts, expect cache benefit only on the tool-loop history breakpoint.

A useful Grafana cache-hit-rate query:

```
sum(rate(claude_cache_read_tokens_total[5m]))
  / sum(rate(claude_cache_read_tokens_total[5m]) + rate(claude_cache_creation_tokens_total[5m]) + rate(claude_input_tokens_total[5m]))
```

## ⚠️ Breaking Change in Phase 1: OpenRouter Bearer auth removed

`API_BASE_URL` must accept `x-api-key` authentication. Until this version, the client auto-detected `anthropic.com` URLs and switched to `Authorization: Bearer` for everything else (typically OpenRouter). That URL-conditional code is gone — both headers are no longer set together; only `x-api-key` is sent.

If you run against OpenRouter via `Authorization: Bearer`, you must put a header-translating proxy in front, or migrate to a different Anthropic-API-compatible provider that accepts `x-api-key`.

## CI & Deployment

GitHub Actions (`.github/workflows/build.yaml`) builds and pushes both images to `ghcr.io` on main branch pushes. Images are tagged with short SHA and `latest`.

- `ghcr.io/<owner>/claude-alert-kubernetes-analyzer` (k8s target)
- `ghcr.io/<owner>/claude-alert-checkmk-analyzer` (checkmk target)
