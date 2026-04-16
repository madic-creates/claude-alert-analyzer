# Agent Log

This file is maintained by the autonomous improvement agent. Read it at the start of each run to understand what has already been done and what remains. Update it after each run.

## Completed Improvements

- **test: k8s handler + isNamespaceAllowed + promqlQuery** (`0ae826a`) — Added `internal/k8s/handler_test.go` with 17 tests covering auth, cooldown dedup, field mapping, queue-full 503, namespace allowlist, and PromQL HTTP client.
- **test: checkmk webhook handler + fingerprint** (`ed1d433`) — Added `internal/checkmk/handler_test.go` with 14 tests covering auth, recovery skipping, severity mapping, cooldown dedup, queue-full, all AlertPayload fields.
- **fix: UTF-8-safe Truncate** (`3b7da9a`) — `Truncate()` in `redact.go` now uses `strings.ToValidUTF8` after byte-slicing to avoid splitting multi-byte characters. Regression tests added.
- **test: ntfy publisher** — Added `internal/shared/ntfy_test.go` with 9 tests covering `Publish` success, headers (Title/Priority/Authorization), no-token path, non-2xx error, body truncation, context cancellation, `Name()`, and `PublishAll` (all succeed, one fails, all fail, empty list).
- **test: k8s context.go** — Added `internal/k8s/context_test.go` with 20 tests covering `GetKubeContext` (no namespace, empty namespace, pod status output, log allowlist enforcement, wildcard allowlist, warning events), `GetPrometheusMetrics` (all alert-name categories: crashloop/memory/cpu/disk/node, namespace sections, result data formatting, unreachable server), and `GatherContext` (four sections returned, non-empty content, Prometheus failure still yields kube context, cancelled context does not block).
- **security: expand RedactSecrets patterns** — Added AWS Access Key ID pattern (`AKIA[0-9A-Z]{16}`) and database connection string pattern covering postgres, mysql, mongodb, redis, amqp URLs with embedded credentials. Added 6 regression tests in `redact_test.go`.
- **feat: ntfy retry with backoff** — `Publish` in `ntfy.go` now retries up to 3 times (2s then 5s delay) on network errors and 5xx responses. 4xx errors are not retried. Context cancellation aborts retries early. Added 4 regression tests in `ntfy_test.go`.
- **fix: two pre-existing test failures** — (1) DB connection-string pattern in `redact.go` moved before the email regex; the email pattern was matching `password@host` before the DB URL pattern ran, leaving the username unredacted. (2) `GetKubeContext` in `context.go` now returns `"(no pods)"` for an empty pod list instead of `""`, consistent with how events returns `"(no warning events)"`; updated `TestGetKubeContext_EmptyNamespace_NoEvents` to match.
- **test: AnalyzeWithClaude** — Added 8 tests in `claude_test.go` covering: success path, multiple text blocks joined with newline, empty content response, non-text blocks ignored, API error in body, HTTP non-2xx error, Anthropic vs OpenRouter auth header selection (via custom `rewriteHostTransport`), and context cancellation. Also included 4 RunToolLoop tests (end_turn, one tool round, max rounds forced summary, HTTP error).
- **fix: runSSHCommand data race** — Replaced shared `output`/`cmdErr` variables (written by the goroutine after timeout returns) with a buffered `chan sshResult`. The goroutine now sends its result into the channel and can always complete without blocking, eliminating the data race. Added three tests in `ssh_test.go` using an in-process SSH server: `TestRunSSHCommand_Success`, `TestRunSSHCommand_CommandError`, and `TestRunSSHCommand_Timeout`.
- **test: RunToolLoop branch coverage** — Added 4 tests covering previously untested paths: API error in JSON body (`resp.Error` field), tool handler returning an error (error string sent as tool_result content), multiple tool calls in a single round (both handlers invoked in order), and forced summary request failing with HTTP error.
- **feat: Prometheus-compatible /metrics endpoint** — Added `internal/shared/metrics.go` with `AlertMetrics` (5 `atomic.Int64` counters: webhooks received, alerts queued, queue full, processed, failed) and `MetricsHandler()` producing Prometheus text format (version 0.0.4). Both `main.go` entrypoints now register `GET /metrics`, wrap the webhook handler to count received requests, and thread `*AlertMetrics` through to `processAlert` for success/failure counting. No new dependencies — standard library only. 6 tests added in `metrics_test.go`.
- **feat: cooldown counter in AlertMetrics** — Added `AlertsCooldown atomic.Int64` to `AlertMetrics` and exposed it as `alert_analyzer_alerts_cooldown_total` in `MetricsHandler()`. Both `HandleWebhook` functions now accept `*shared.AlertMetrics` (nil-safe) and increment `AlertsCooldown` when an alert is skipped due to deduplication cooldown. Both `main.go` entrypoints pass `metrics` to the handler. 2 new tests (`TestHandleWebhook_CooldownIncrementsMetric`, `TestCheckmkHandleWebhook_CooldownIncrementsMetric`) verify counter behavior; existing handler tests updated to pass `nil` metrics.
- **fix: cooldown eviction cap removed** — Removed the `evicted < 100` guard from `CooldownManager.CheckAndSet`. The loop already iterates all entries O(n), so the cap provided no performance benefit while preventing full cleanup of expired entries when more than 100 expired at once. Regression test `TestCooldown_ExpiredEntriesFullyEvicted` added (150 entries, verifies map shrinks to 1 after eviction trigger).

## Test Coverage Status

| Package | Source Files | Test Files | Coverage Notes |
|---|---|---|---|
| `internal/shared/` | claude.go, cooldown.go, metrics.go, ntfy.go, redact.go, types.go | claude_test.go, cooldown_test.go, metrics_test.go, ntfy_test.go, redact_test.go, types_test.go | All files covered; cooldown eviction now fully tested (including >100 entries) |
| `internal/k8s/` | handler.go, context.go, types.go | handler_test.go, context_test.go | `context.go` fully covered: GatherContext, GetKubeContext, GetPrometheusMetrics all tested directly with fake k8s client and httptest |
| `internal/checkmk/` | agent.go, context.go, handler.go, ssh.go, types.go | agent_test.go, context_test.go, handler_test.go, ssh_test.go | Good coverage; `ssh.go` now has success, command-error, and timeout tests via in-process server |
| `cmd/k8s-analyzer/` | main.go | none | Entrypoint, hard to unit test |
| `cmd/checkmk-analyzer/` | main.go | none | Entrypoint, hard to unit test |

## Potential Next Improvements

_(no items pending)_
