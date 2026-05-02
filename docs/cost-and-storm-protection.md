# Cost & Storm Protection — Operations Guide

Practical guide for operators running the alert analyzers under cost or load
pressure. Phase 1 ships with prompt caching, severity-based routing, and
token-cost metrics. Phase 2 (storm-mode, circuit-breaker, group-cooldown) is
not yet implemented.

## At a glance

| What | Default | How to enable |
|---|---|---|
| Prompt caching | **On** (transparent) | Always active — no opt-in |
| Severity-based model routing | Off | Set any `CLAUDE_MODEL_<SEVERITY>` env var |
| Severity-based agent rounds | Off | Set any `MAX_AGENT_ROUNDS_<SEVERITY>` env var |
| Token-cost metrics | **On** | Always exposed on `:METRICS_PORT/metrics` |

Defaults preserve previous behavior. After upgrading without setting the new
env vars, the only observable change is that Anthropic's prompt-cache
discount kicks in and the four `claude_*_tokens_total` metrics start
populating.

## Environment variables

Optional. All severity-specific overrides fall back to the existing
`CLAUDE_MODEL` / `MAX_AGENT_ROUNDS` values when unset.

```
CLAUDE_MODEL_CRITICAL          — model for severity=critical (default: $CLAUDE_MODEL)
CLAUDE_MODEL_WARNING           — model for severity=warning  (default: $CLAUDE_MODEL)
CLAUDE_MODEL_INFO              — model for severity=info     (default: $CLAUDE_MODEL)

MAX_AGENT_ROUNDS_CRITICAL      — tool-loop budget, range 0-50 (default: $MAX_AGENT_ROUNDS)
MAX_AGENT_ROUNDS_WARNING       — same, range 0-50             (default: $MAX_AGENT_ROUNDS)
MAX_AGENT_ROUNDS_INFO          — same, range 0-50             (default: $MAX_AGENT_ROUNDS)
```

**`MAX_AGENT_ROUNDS_<SEVERITY>=0`** is the static-only mode: Claude gets the
pre-fetched context (Prometheus metrics, kube events, pod logs for k8s; SSH
diagnostics + host services for checkmk) but **no tools**. One API call per
alert, no multi-round conversation. Cheapest option.

Validation runs at startup. An out-of-range value kills the process with a
clear error message — no silent fallback.

## Severity mapping

The free-form `severity` label is normalized to one of three buckets that
the policy uses for routing:

**Alertmanager** (`severity` label, case-insensitive)

| Label | Bucket |
|---|---|
| `critical`, `page` | critical |
| `warning`, `notice` | warning |
| `info` | info |
| anything else / missing | warning (defensive default) |

**CheckMK** (`SERVICESTATE` then `HOSTSTATE` fallback)

| State | Bucket |
|---|---|
| `CRITICAL` | critical |
| `WARNING` | warning |
| `UNKNOWN` | warning (defensive default) |
| host `DOWN` / `UNREACHABLE` (when no `SERVICESTATE`) | critical |
| anything else | warning |

The defensive default to `warning` is intentional: better to pay for an
unnecessary analysis than to silently downgrade a real critical.

## Recommended setups

Three example configurations. Pick the one closest to your situation, then
tune.

### Conservative (no cost-sensitive routing yet)

Starting point right after upgrade. Caching only.

```bash
# No new env vars set.
# Cache discount kicks in; cost reduction depends on prompt size.
```

Verify cache works after some traffic. Move to the next tier when
operationally comfortable.

### Balanced (typical setup)

Haiku for non-criticals, Opus for criticals, Info gets static analysis only.

```bash
CLAUDE_MODEL=claude-opus-4-7
CLAUDE_MODEL_WARNING=claude-haiku-4-5
CLAUDE_MODEL_INFO=claude-haiku-4-5
MAX_AGENT_ROUNDS=10
MAX_AGENT_ROUNDS_INFO=0
```

Effective cost reduction for noisy info alerts: **~95%** (Haiku is ~12×
cheaper than Opus per token, and dropping the tool loop removes the
N-rounds-of-context-replay multiplier).

### Aggressive (high-volume, narrow critical scope)

Static-only for everything except critical. Tool loops are reserved for the
small number of alerts where the additional diagnostic depth pays off.

```bash
CLAUDE_MODEL=claude-opus-4-7
CLAUDE_MODEL_WARNING=claude-haiku-4-5
CLAUDE_MODEL_INFO=claude-haiku-4-5
MAX_AGENT_ROUNDS=10
MAX_AGENT_ROUNDS_WARNING=0
MAX_AGENT_ROUNDS_INFO=0
```

Risk: warning alerts get a one-shot analysis without follow-up tool calls.
Watch the analysis quality on a sample of warnings before fully committing.

## Metrics & dashboards

Four new counters, all on `:METRICS_PORT/metrics`. Labels:
`{source, severity, model}`. (Phase 1 records `severity="all"` because
per-call severity isn't threaded into the API client yet — refined in a
later iteration.)

| Metric | Meaning |
|---|---|
| `claude_input_tokens_total` | Regular input tokens (excluding cache hits) |
| `claude_output_tokens_total` | Output tokens generated |
| `claude_cache_creation_tokens_total` | Tokens that produced new cache entries (~25% surcharge) |
| `claude_cache_read_tokens_total` | Tokens served from cache (~10% of regular input cost) |

### Cache hit rate (the most important derived signal)

```promql
sum(rate(claude_cache_read_tokens_total[5m]))
/
sum(
  rate(claude_cache_read_tokens_total[5m])
  + rate(claude_cache_creation_tokens_total[5m])
  + rate(claude_input_tokens_total[5m])
)
```

**Healthy ranges:**
- Below 30%: caching probably isn't paying off. Check the troubleshooting
  section.
- 30–60%: working but room to grow. Likely the system prompt is below
  Anthropic's ~1024-token caching threshold and only the tool-loop history
  cache is firing.
- Above 60%: caching is doing its job. Storm bursts in particular will hit
  the high end here.

### Estimated daily token spend

Replace `INPUT_PRICE_PER_TOKEN`, `OUTPUT_PRICE_PER_TOKEN`, etc. with values
from your Anthropic pricing page.

```promql
# Approximate cost per second
  sum(rate(claude_input_tokens_total[5m]))         * <input_price>
+ sum(rate(claude_output_tokens_total[5m]))        * <output_price>
+ sum(rate(claude_cache_creation_tokens_total[5m])) * <input_price * 1.25>
+ sum(rate(claude_cache_read_tokens_total[5m]))    * <input_price * 0.10>
```

### What to alert on

Defensive alerts that catch cost surprises before they become bills.

```promql
# Sudden token spike (>3× the rolling 1h baseline)
sum(rate(claude_input_tokens_total[5m]))
>
3 * sum(rate(claude_input_tokens_total[1h] offset 1h))
```

```promql
# Cache hit rate collapses (e.g. operator pushed a system-prompt change
# that made it shorter than the cache threshold)
( <cache hit rate query above> ) < 0.20
```

```promql
# Output tokens climbing without input — probably an analysis loop
# that's burning rounds. Phase 2 will gate this with the circuit-breaker.
rate(claude_output_tokens_total[5m]) /
  rate(claude_input_tokens_total[5m]) > 0.15
```

## Rollout playbook

For a fresh deploy of the Phase 1 changes:

1. **Deploy with no new env vars.** Caching alone reduces cost; behavior is
   otherwise identical.
2. **Wait 24–72 hours.** Watch the cache hit rate and total token rates
   stabilize. Confirm no regressions in alerts-analyzed counts.
3. **Enable severity-based model routing.** Add
   `CLAUDE_MODEL_WARNING=claude-haiku-4-5` and
   `CLAUDE_MODEL_INFO=claude-haiku-4-5`. Redeploy. Watch a sample of
   warning analyses for quality regressions.
4. **Enable static-only mode for info.** Add `MAX_AGENT_ROUNDS_INFO=0`.
   Redeploy. Info alerts now skip the tool loop entirely.
5. **Tighten if needed.** If cost is still a concern after step 4, consider
   `MAX_AGENT_ROUNDS_WARNING=0` (aggressive setup). Otherwise stop here.

Each step is independently revertible — just remove the env var and
redeploy.

## Troubleshooting

### Cache hit rate stays near 0%

- **System prompt under the threshold.** Anthropic only caches blocks ≥1024
  tokens (Sonnet/Opus) or ≥2048 (Haiku). The system prompts in this repo
  are deliberately compact, so for single-turn `Analyze` calls (especially
  with `MAX_AGENT_ROUNDS_*=0`) the cache may not fire at all. The dominant
  cache benefit is on the tool-loop history breakpoint, which only matters
  in multi-round loops.
- **Provider doesn't support `cache_control`.** Most Anthropic-API-
  compatible providers do, but if you're hitting a relay that strips
  unknown fields, no creation tokens will appear. Confirm by reading a raw
  response from the provider — the `usage` block must include
  `cache_creation_input_tokens` and `cache_read_input_tokens`.
- **Traffic too sparse for the 5-minute Anthropic cache TTL.** If alerts
  arrive less than once every 5 minutes, every request is a cache miss.
  This is fine; caching isn't useful in that regime anyway.

### Severity overrides don't seem to apply

- **Check the startup log.** It prints `modelOverrides=N` and
  `roundsOverrides=N`. If both are 0, no override env vars were picked up
  (typo? missing in the deployment manifest?).
- **Severity bucket mismatch.** A label like `severity=high` falls into
  `warning` per the defensive default — not `critical`. If you have custom
  severity labels, normalize them upstream in the alertmanager rule before
  they hit the analyzer.
- **CheckMK sends a host-only notification.** If `SERVICESTATE` is empty
  and `HOSTSTATE` is e.g. `UP`, the bucket is `warning`. Only `DOWN` /
  `UNREACHABLE` map to `critical` for hosts.

### Analyzer fails to start: `policy: MAX_AGENT_ROUNDS_X=N: must be between 0 and 50`

Out-of-range override. Fix the env var. Range is `[0, 50]` for the
per-severity overrides (0 enables static-only mode); the global
`MAX_AGENT_ROUNDS` is `[1, 50]` (cannot disable the tool loop globally —
use the per-severity overrides for that).

### Authentication suddenly broken after upgrade

You probably ran against OpenRouter using `Authorization: Bearer`. The
URL-conditional Bearer path was removed in this phase. OpenRouter
compatibility will return in a follow-up that migrates the analyzer to the
official `anthropic-sdk-go`, which honors the standard
`ANTHROPIC_AUTH_TOKEN` / `ANTHROPIC_BASE_URL` env vars. Until then, point
`API_BASE_URL` at `api.anthropic.com` directly or use a different
`x-api-key`-compatible relay.

## Breaking change in Phase 1: OpenRouter Bearer auth removed

The client used to detect non-`anthropic.com` URLs and switch to
`Authorization: Bearer`. That URL-conditional code is gone. The client now
always sends `x-api-key` + `anthropic-version`.

If you point `API_BASE_URL` at OpenRouter, you must currently:
- Migrate to an Anthropic-compatible provider that accepts `x-api-key`
  directly, or
- Run against `api.anthropic.com` directly.

A follow-up phase will migrate the analyzer to the official
`anthropic-sdk-go`, which honors the standard `ANTHROPIC_AUTH_TOKEN` /
`ANTHROPIC_BASE_URL` env vars used by Anthropic's other clients (Claude
Code, Python/JS SDKs). That restores OpenRouter compatibility via env
vars alone — no proxy.

The change in this phase reduces the auth code path to one branch and
unblocks the prompt-caching headers; keeping a divergent code path for
one provider's auth was not justified inside a hand-rolled HTTP client.

## Phase 2 (planned, not shipped)

Three additional protections are designed but not yet implemented:

- **Group-cooldown**: dedup at `alertname+namespace` (k8s) /
  `host+service` (checkmk) granularity in addition to fingerprint.
  Storms from many similar alerts collapse to one analysis.
- **Storm-mode**: sliding-window detector that forces `rounds=0` cluster-
  wide when alert rate exceeds a threshold, plus an aggregated ntfy
  notification instead of per-alert messages.
- **Circuit-breaker**: opens after consecutive Anthropic API failures,
  blocks further calls for a cooldown window, half-open probe on recovery.
  Gates at the analysis level so a probe is exactly one analysis (not one
  HTTP round-trip).

When Phase 2 ships, this document will gain corresponding env-var
references and rollout steps. Spec lives at
`docs/superpowers/specs/2026-05-01-storm-cost-protection-design.md`.
