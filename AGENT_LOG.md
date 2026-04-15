# Agent Log

This file is maintained by the autonomous improvement agent. Read it at the start of each run to understand what has already been done and what remains. Update it after each run.

## Test Coverage Status

| Package | Source Files | Test Files | Coverage Notes |
|---|---|---|---|
| `internal/shared/` | claude.go, cooldown.go, ntfy.go, redact.go, types.go | claude_test.go, cooldown_test.go, redact_test.go, types_test.go | `ntfy.go` has no tests |
| `internal/k8s/` | handler.go, context.go, types.go | handler_test.go | `context.go` (GatherContext, GetKubeContext, GetPrometheusMetrics) partially covered via handler tests; no dedicated context_test.go |
| `internal/checkmk/` | agent.go, context.go, handler.go, ssh.go, types.go | agent_test.go, context_test.go, handler_test.go, ssh_test.go | Good coverage |
| `cmd/k8s-analyzer/` | main.go | none | Entrypoint, hard to unit test |
| `cmd/checkmk-analyzer/` | main.go | none | Entrypoint, hard to unit test |

## Completed Improvements

- **test: k8s handler + isNamespaceAllowed + promqlQuery** (`0ae826a`) — Added `internal/k8s/handler_test.go` with 17 tests covering auth, cooldown dedup, field mapping, queue-full 503, namespace allowlist, and PromQL HTTP client.
- **test: checkmk webhook handler + fingerprint** (`ed1d433`) — Added `internal/checkmk/handler_test.go` with 14 tests covering auth, recovery skipping, severity mapping, cooldown dedup, queue-full, all AlertPayload fields.
- **fix: UTF-8-safe Truncate** (`3b7da9a`) — `Truncate()` in `redact.go` now uses `strings.ToValidUTF8` after byte-slicing to avoid splitting multi-byte characters. Regression tests added.

## Potential Next Improvements

- **`internal/shared/ntfy.go`** — No tests at all. The `Publish` function makes HTTP calls; worth adding httptest-based tests.
- **`internal/k8s/context.go`** — `GatherContext`, `GetKubeContext` have no dedicated tests (only indirectly tested). Could add a `context_test.go` using `k8s.io/client-go/kubernetes/fake`.
- **Reliability: ntfy retry** — `Publish` in `ntfy.go` has no retry logic; a transient ntfy outage silently drops the analysis result.
- **Reliability: Claude API timeout** — The HTTP client in `claude.go` uses no explicit timeout beyond what the caller's context provides.
- **Security: `RedactSecrets` patterns** — Review regex patterns for completeness; consider adding patterns for common token formats (Bearer tokens, AWS keys).
- **Observability** — No structured logging or metrics anywhere; all log output is `log.Printf`.
