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

Common optional: `PORT` (default `8080`), `METRICS_PORT` (default `9101`), `NTFY_PUBLISH_URL`, `NTFY_PUBLISH_TOPIC`, `NTFY_PUBLISH_TOKEN`, `CLAUDE_MODEL`, `API_BASE_URL`, `COOLDOWN_SECONDS`, `LOG_LEVEL`, `MAX_AGENT_ROUNDS` (default `10`, tool-loop budget).
k8s optional: `MAX_LOG_BYTES`, `PROMETHEUS_URL`, `SKIP_RESOLVED`.

Severity-based overrides (`CLAUDE_MODEL_<SEVERITY>`, `MAX_AGENT_ROUNDS_<SEVERITY>`) are operator-facing and documented in [`docs/cost-and-storm-protection.md`](docs/cost-and-storm-protection.md).

k8s-analyzer runs in-cluster only (`rest.InClusterConfig()`).

## Cost & Storm Protection

Phase 1 ships three operator-facing features: prompt caching (always on), severity-based model and tool-round routing (opt-in via env vars), and four token-cost Prometheus counters. Architectural touchpoints when working in this code:

- `internal/shared/severity.go` — `Severity` enum + `SeverityFromAlertmanager` / `SeverityFromCheckMK` normalizers. Set on `AlertPayload.SeverityLevel` in each handler.
- `internal/shared/policy.go` — `AnalysisPolicy` decision layer. `ModelFor(sev)` and `MaxRoundsFor(sev)` are the two routing entry points called from each pipeline. `LoadPolicy(BaseConfig)` reads the optional env vars.
- `internal/shared/claude.go` — Cache breakpoints set at three levels: `systemBlocks()` helper, `withCachedTail()` helper for tools, and an inline assignment on the last `tool_result` of each `RunToolLoop` round.
- Pipelines (`internal/k8s/pipeline.go`, `internal/checkmk/pipeline.go`) branch on `policy.MaxRoundsFor(...) == 0` to call `Analyzer.Analyze` (static-only) instead of `RunAgenticDiagnostics`.

⚠️ **Breaking change**: `Authorization: Bearer` removed; `API_BASE_URL` must accept `x-api-key`. OpenRouter compatibility is deferred to a planned follow-up that migrates the client to `anthropic-sdk-go` (which honors `ANTHROPIC_AUTH_TOKEN` natively). Migration notes in `docs/cost-and-storm-protection.md`.

Phase 2 (storm-mode, circuit-breaker, group-cooldown) is designed but not yet implemented — see `docs/superpowers/specs/2026-05-01-storm-cost-protection-design.md` for the full design.

## CI & Deployment

GitHub Actions (`.github/workflows/build.yaml`) builds and pushes both images to `ghcr.io` on main branch pushes. Images are tagged with short SHA and `latest`.

- `ghcr.io/<owner>/claude-alert-kubernetes-analyzer` (k8s target)
- `ghcr.io/<owner>/claude-alert-checkmk-analyzer` (checkmk target)
