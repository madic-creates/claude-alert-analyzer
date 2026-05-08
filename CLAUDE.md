# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Two independent alert analyzer services that receive monitoring webhooks, gather diagnostic context, send the context to the Claude API for root-cause analysis, and publish the analysis to ntfy. Both share a common library but are separate binaries with separate Dockerfile targets.

- **k8s-analyzer** — Receives Alertmanager webhooks, runs static prefetch (Prometheus metrics + Kubernetes events/pods/logs) plus an agentic Claude tool-loop (`kubectl_exec`, `promql_query`) for root-cause analysis.
- **checkmk-analyzer** — Receives CheckMK notification webhooks, gathers CheckMK host services + SSH diagnostics, analyzes via Claude API

## Build & Test

Go 1.26+, no CGO dependencies.

```bash
# Build both binaries (or use the underlying go build commands directly)
make binaries

# Run all tests
go test ./...

# Run tests for a specific package
go test ./internal/shared/
go test ./internal/checkmk/

# Docker images: the Dockerfile expects prebuilt binaries in the build
# context, so binaries must exist on disk first. `make images` does both
# steps in order.
make images
```

**Note:** The Dockerfile no longer compiles Go. Always run `make binaries`
(or the equivalent `go build` commands) before `docker build`. CI does this
automatically in the `build` job and feeds the binaries to image builds via
workflow artifacts.

## Architecture

### Processing Pipeline (same for both analyzers)

```
Webhook → Auth check → Cooldown dedup → Work queue (buffered chan, 5 workers)
  → Context gathering (parallel) → Claude API analysis → ntfy publish
```

### Package Layout

- `internal/shared/` — Common types (`AlertPayload`, `BaseConfig`, `AnalysisContext`), Claude API client (plain `Analyze` + multi-turn `RunToolLoop`, both threading `Severity` through), `Analyzer`/`ToolLoopRunner` interfaces, ntfy publisher, cooldown manager (`CheckAndSetWithGroup` returns a typed `CooldownOutcome`), secret redaction, shared HTTP server + worker pool (`Server` in `server.go`), method-only `AlertMetrics` façade and `PrometheusMetrics` (constructor takes a `Product` enum and applies it as a `ConstLabel`) exposed at `/metrics` on a separate port via `promhttp.HandlerFor`
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
- **API flexibility**: Claude API client uses the Anthropic Messages API format via `anthropic-sdk-go`. Either Anthropic's native `x-api-key` (`ANTHROPIC_API_KEY`) or OpenRouter-style `Authorization: Bearer` (`ANTHROPIC_AUTH_TOKEN`) is supported — the SDK selects the right header based on which env var is set. See "Claude SDK integration" below.
- **Metrics**: All metrics share the `alert_analyzer_*` prefix and carry a `product` ConstLabel (`k8s` | `checkmk`) applied at registry construction. Standard `go_*` and `process_*` collectors register on the same private registry via `WrapRegistererWith`. Served on `METRICS_PORT` (separate from the webhook port). Full metric reference: [`docs/observability.md`](docs/observability.md).
- **Claude SDK integration**: The Claude API client wraps `github.com/anthropics/anthropic-sdk-go` with a `LimitedTransport` for body capping and latency observation. Auth is configured via `ANTHROPIC_API_KEY` (sets `x-api-key`) or `ANTHROPIC_AUTH_TOKEN` (sets `Authorization: Bearer`); exactly one of the two must be set. Setting both at startup is a fatal error.

## Environment Variables

Both analyzers require: `WEBHOOK_SECRET`, plus exactly one of `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN`
CheckMK additionally requires: `CHECKMK_API_USER`, `CHECKMK_API_SECRET`

Common optional: `PORT` (default `8080`), `METRICS_PORT` (default `9101`), `NTFY_PUBLISH_URL`, `NTFY_PUBLISH_TOPIC`, `NTFY_PUBLISH_TOKEN`, `CLAUDE_MODEL`, `ANTHROPIC_BASE_URL`, `COOLDOWN_SECONDS`, `LOG_LEVEL`, `MAX_AGENT_ROUNDS` (default `10`, tool-loop budget).
k8s optional: `MAX_LOG_BYTES`, `PROMETHEUS_URL`, `SKIP_RESOLVED`.

Severity-based overrides (`CLAUDE_MODEL_<SEVERITY>`, `MAX_AGENT_ROUNDS_<SEVERITY>`) are operator-facing and documented in [`docs/cost-and-storm-protection.md`](docs/cost-and-storm-protection.md).

Storm-robustness optional: `GROUP_COOLDOWN_SECONDS` (default 0 = disabled),
`STORM_MODE_THRESHOLD` (default 0), `STORM_MODE_NOTIFY_INTERVAL` (default 60s),
`CIRCUIT_BREAKER_THRESHOLD` (default 0), `CIRCUIT_BREAKER_OPEN_SECONDS` (default 60),
`CIRCUIT_BREAKER_MAX_PROBE_SECONDS` (default 60),
`CIRCUIT_BREAKER_NOTIFY_INTERVAL` (default 300s).

k8s-analyzer runs in-cluster only (`rest.InClusterConfig()`).

## Cost & Storm Protection

Two coupled feature groups in `internal/shared/`:

**Cost optimization** (caching + severity routing):

- `internal/shared/severity.go` — `Severity` enum + `SeverityFromAlertmanager` / `SeverityFromCheckMK` normalizers. Set on `AlertPayload.SeverityLevel` in each handler.
- `internal/shared/policy.go` — `AnalysisPolicy` decision layer. `ModelFor(sev)` and `MaxRoundsFor(sev)` are the two routing entry points called from each pipeline. `LoadPolicy(BaseConfig)` reads the optional env vars.
- `internal/shared/claude.go` — Cache breakpoints set at three levels: `systemBlocks()` helper, `withCachedTail()` helper for tools, and an inline assignment on the last `tool_result` of each `RunToolLoop` round.
- Pipelines (`internal/k8s/pipeline.go`, `internal/checkmk/pipeline.go`) branch on `policy.MaxRoundsFor(...) == 0` to call `Analyzer.Analyze` (static-only) instead of `RunAgenticDiagnostics`.

**Storm robustness** (group-cooldown + storm-mode + circuit-breaker):

- `internal/shared/cooldown.go` — atomic `CheckAndSetWithGroup` for combined fingerprint+group cooldowns with rollback semantics; lock hierarchy `groupMu < fpMu`.
- `internal/shared/storm.go` — `StormDetector` (5-min sliding window). Triggers `Policy.IsDegraded()` which forces `rounds=0` in the pipeline.
- `internal/shared/breaker.go` — `CircuitBreaker` with Permit-Token API (`Acquire()` → `*Permit`, `permit.Done(err)`). Probe-watchdog auto-releases stuck probes.
- `internal/shared/notify_aggregator.go` — single-owner-goroutine aggregator with request/reply Stop; used by both storm and breaker for collapsed notifications.
- Pipelines track `phase failurePhase` + `analysisErr` (separate from named return) so the deferred cooldown-cleanup is correct for `ErrCircuitOpen` and post-API failures (Verstärker-Bug fix).
- All storm-robustness features default disabled. See [`docs/cost-and-storm-protection.md`](docs/cost-and-storm-protection.md) for operator guidance and [`docs/cost-and-storm-protection-internals.md`](docs/cost-and-storm-protection-internals.md) for component architecture.

Design spec: `docs/superpowers/specs/2026-05-01-storm-cost-protection-design.md`.

## CI & Deployment

GitHub Actions (`.github/workflows/build.yaml`) builds and pushes both images to `ghcr.io` on main branch pushes. Images are tagged with short SHA and `latest`.

- `ghcr.io/<owner>/claude-alert-kubernetes-analyzer` (k8s target)
- `ghcr.io/<owner>/claude-alert-checkmk-analyzer` (checkmk target)
