# Agent Log

This file is maintained by the autonomous improvement agent. Read it at the start of each run to understand what has already been done and what remains. Update it after each run.

## Completed Improvements

- **test: k8s handler + isNamespaceAllowed + promqlQuery** (`0ae826a`) — Added `internal/k8s/handler_test.go` with 17 tests covering auth, cooldown dedup, field mapping, queue-full 503, namespace allowlist, and PromQL HTTP client.
- **test: checkmk webhook handler + fingerprint** (`ed1d433`) — Added `internal/checkmk/handler_test.go` with 14 tests covering auth, recovery skipping, severity mapping, cooldown dedup, queue-full, all AlertPayload fields.
- **fix: UTF-8-safe Truncate** (`3b7da9a`) — `Truncate()` in `redact.go` now uses `strings.ToValidUTF8` after byte-slicing to avoid splitting multi-byte characters. Regression tests added.
- **test: ntfy publisher** — Added `internal/shared/ntfy_test.go` with 9 tests covering `Publish` success, headers (Title/Priority/Authorization), no-token path, non-2xx error, body truncation, context cancellation, `Name()`, and `PublishAll` (all succeed, one fails, all fail, empty list).
- **test: k8s context.go** — Added `internal/k8s/context_test.go` with 20 tests covering `GetKubeContext` (no namespace, empty namespace, pod status output, log allowlist enforcement, wildcard allowlist, warning events), `GetPrometheusMetrics` (all alert-name categories: crashloop/memory/cpu/disk/node, namespace sections, result data formatting, unreachable server), and `GatherContext` (four sections returned, non-empty content, Prometheus failure still yields kube context, cancelled context does not block).
- **security: expand RedactSecrets patterns** — Added AWS Access Key ID pattern (`AKIA[0-9A-Z]{16}`) and database connection string pattern covering postgres, mysql, mongodb, redis, amqp URLs with embedded credentials. Added 6 regression tests in `redact_test.go`.

## Test Coverage Status

| Package | Source Files | Test Files | Coverage Notes |
|---|---|---|---|
| `internal/shared/` | claude.go, cooldown.go, ntfy.go, redact.go, types.go | claude_test.go, cooldown_test.go, ntfy_test.go, redact_test.go, types_test.go | All files covered |
| `internal/k8s/` | handler.go, context.go, types.go | handler_test.go, context_test.go | `context.go` fully covered: GatherContext, GetKubeContext, GetPrometheusMetrics all tested directly with fake k8s client and httptest |
| `internal/checkmk/` | agent.go, context.go, handler.go, ssh.go, types.go | agent_test.go, context_test.go, handler_test.go, ssh_test.go | Good coverage |
| `cmd/k8s-analyzer/` | main.go | none | Entrypoint, hard to unit test |
| `cmd/checkmk-analyzer/` | main.go | none | Entrypoint, hard to unit test |

## Potential Next Improvements

- **Reliability: ntfy retry** — `Publish` in `ntfy.go` has no retry logic; a transient ntfy outage silently drops the analysis result.
- **Reliability: Claude API timeout** — The HTTP client in `claude.go` uses no explicit timeout beyond what the caller's context provides.
- **Observability** — No structured logging or metrics anywhere; all log output is `log.Printf`.
