# Development

Everything below is only relevant if you want to build, test, or modify the analyzer itself. For running it, the install guides ([k8s](install-k8s.md), [checkmk](install-checkmk.md)) are sufficient.

## Prerequisites

- Go 1.26+ (no CGO)
- Docker (for container builds)

## Build

```bash
# Build both binaries
make binaries

# Build both Docker images (runs `make binaries` first, then docker build).
# The Dockerfile expects prebuilt binaries in the build context — it does
# not compile Go itself. CI mirrors this: a `build` job produces the
# binaries and feeds them to image builds via workflow artifacts.
make images
```

## Test

```bash
# All tests
go test ./...

# Specific package
go test ./internal/shared/
go test ./internal/checkmk/

# Race detector (as in CI)
go test -race -count=1 ./...
```

## Project layout

- `internal/shared/` — common types (`AlertPayload`, `BaseConfig`, `AnalysisContext`), Claude API client, ntfy publisher, cooldown manager, secret redaction, HTTP server scaffolding, metrics
- `internal/k8s/` — Alertmanager webhook handler, Prometheus queries, Kubernetes context gathering (events, pod status, logs), agentic tool-loop runner (`RunAgenticDiagnostics` in `agent.go`)
- `internal/checkmk/` — CheckMK webhook handler, CheckMK REST API client, agentic SSH runner with alert-category detection (CPU/disk/memory/service)
- `cmd/k8s-analyzer/` and `cmd/checkmk-analyzer/` — entrypoints: config loading, worker pool, HTTP server, graceful shutdown

## Key patterns

- **Alert normalization** — both sources convert into `shared.AlertPayload` with a `Fields map[string]string` for source-specific data. k8s uses `label:` and `annotation:` prefixed keys.
- **Context gathering** — each analyzer exposes `GatherContext(...)` returning `shared.AnalysisContext` (a list of named sections rendered into the prompt). Data collection runs concurrently: k8s fans out Prometheus + kube context; checkmk fans out host services + SSH.
- **Agentic loops** — after static context gathering, both analyzers run `RunAgenticDiagnostics` which drives a multi-turn Claude tool-use loop. k8s exposes `kubectl_exec` and `promql_query`; checkmk exposes SSH command execution. Round budget is capped by `MAX_AGENT_ROUNDS`.
- **Cooldown dedup** — `CooldownManager` prevents re-analyzing the same alert within the configured TTL. The cooldown is cleared on analysis failure so retries work.
- **Provider flexibility** — the Claude client routes through `anthropic-sdk-go`. Either Anthropic's native `x-api-key` (`ANTHROPIC_API_KEY`) or OpenRouter-style `Authorization: Bearer` (`ANTHROPIC_AUTH_TOKEN`) is supported; the SDK selects the right header based on which env var is set.
- **Cost routing** — `internal/shared/policy.go` (`AnalysisPolicy`) maps `Severity` → model + tool-loop rounds. Pipelines branch on `MaxRoundsFor() == 0` to call `Analyze` instead of `RunToolLoop`. Prompt caching is set at three breakpoints in `internal/shared/claude.go` (system, last tool, last `tool_result` per round).

## Pre-commit

This repo uses [pre-commit](https://pre-commit.com/) for local hygiene (trailing whitespace, line endings, private-key detection, smart-quote fixup, `golangci-lint --new-from-rev HEAD --fix`, `go test` on staged packages). Install once with `pre-commit install`. See [pre-commit.md](pre-commit.md).

## CI/CD

GitHub Actions ([`build.yaml`](../.github/workflows/build.yaml)) runs `test`, `lint`, and `build` in parallel, then a `release` job downloads the prebuilt binaries as artifacts, builds and pushes both images to GHCR, and publishes a semantic-release tag with attached binaries on every qualifying push to `main`:

- `ghcr.io/madic-creates/claude-alert-kubernetes-analyzer:{vX.Y.Z,X.Y.Z,X.Y,latest}`
- `ghcr.io/madic-creates/claude-alert-checkmk-analyzer:{vX.Y.Z,X.Y.Z,X.Y,latest}`

The workflow triggers on every push to `main` that touches `cmd/`, `internal/`, `Dockerfile`, `Makefile`, `go.mod`, `go.sum`, the workflow file itself, or `.semrelrc`. Steps:

1. **`test`** — `go vet` + `go test -race -count=1`.
2. **`lint`** — `golangci-lint`.
3. **`build`** — compiles both binaries via `make binaries` and uploads them as a `binaries` artifact (retention 1 day).
4. **`release`** — downloads the artifact, runs semantic-release (dry-run) to determine the next version, builds and pushes both images using the prebuilt binaries (the Dockerfile only `COPY`s, no Go toolchain inside Docker), publishes the Git tag + GitHub Release, and uploads the binaries with sha256 checksums to the release.

To pin a specific build, reference the `vX.Y.Z` tag in your deployment manifest.

## Maintenance

- **Dependency updates** — Renovate runs daily against Go modules, Docker base images, GitHub Actions, and pre-commit hook versions. Patch and minor updates automerge; major updates require manual approval. See [renovate.md](renovate.md).
- **GHCR image cleanup** — A weekly workflow prunes old versions (semver tags are kept forever; sha-tagged/untagged versions keep the newest `KEEP_TAGGED`, default 10; manifest children of kept versions are never deleted). See [cleanup-ghcr.md](cleanup-ghcr.md).
