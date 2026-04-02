# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Two independent alert analyzer services that receive monitoring webhooks, gather diagnostic context, send the context to the Claude API for root-cause analysis, and publish the analysis to ntfy. Both share a common library but are separate binaries with separate Dockerfile targets.

- **k8s-analyzer** — Receives Alertmanager webhooks, gathers Prometheus metrics + Kubernetes events/pods/logs, analyzes via Claude API
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

- `internal/shared/` — Common types (`AlertPayload`, `BaseConfig`, `AnalysisContext`), Claude API client, ntfy publisher, cooldown manager, secret redaction utilities
- `internal/k8s/` — Alertmanager webhook handler, Prometheus PromQL queries, Kubernetes context gathering (events, pod status, logs with namespace allowlist)
- `internal/checkmk/` — CheckMK webhook handler, CheckMK REST API client, SSH diagnostic runner with alert category detection (CPU/disk/memory/service)
- `cmd/k8s-analyzer/` and `cmd/checkmk-analyzer/` — Entrypoints with config loading, worker pool, HTTP server, graceful shutdown

### Key Design Patterns

- **Alert normalization**: Both sources convert to `shared.AlertPayload` with `Fields map[string]string` for source-specific data. k8s uses `label:` and `annotation:` prefixed keys.
- **Context gathering pattern**: Each analyzer exports a `GatherContext(...)` function that returns `shared.AnalysisContext` — a list of named sections rendered into the Claude prompt.
- **Cooldown dedup**: `CooldownManager` prevents re-analyzing the same alert within a configurable TTL. Cooldown is cleared on analysis failure so retries work.
- **Context gathering**: Runs data collection concurrently (goroutines + channels). CheckMK gathers host services + SSH in parallel; k8s gathers Prometheus + kube context in parallel.
- **Security**: Pod logs only collected from allowlisted namespaces (`ALLOWED_NAMESPACES`). All gathered output passes through `RedactSecrets()`. SSH commands use strict known_hosts and input validation.
- **API flexibility**: Claude API client auto-detects Anthropic vs OpenRouter based on URL (sets `x-api-key` vs `Authorization: Bearer`).

## Environment Variables

Both analyzers require: `WEBHOOK_SECRET`, `API_KEY`
CheckMK additionally requires: `CHECKMK_API_USER`, `CHECKMK_API_SECRET`

k8s-analyzer runs in-cluster only (`rest.InClusterConfig()`).

## CI & Deployment

GitHub Actions (`.github/workflows/build.yaml`) builds and pushes both images to `ghcr.io` on main branch pushes. Images are tagged with short SHA and `latest`.

- `ghcr.io/<owner>/claude-alert-kubernetes-analyzer` (k8s target)
- `ghcr.io/<owner>/claude-alert-checkmk-analyzer` (checkmk target)
