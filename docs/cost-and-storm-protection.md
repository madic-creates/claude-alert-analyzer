# Cost & Storm Protection — Operations Guide

Practical guide for operators running the alert analyzers under cost or
load pressure. The analyzers ship with prompt caching, severity-based
routing, token-cost metrics, group-cooldown, storm-mode, and a Claude-API
circuit-breaker — most disabled by default and opt-in via env var.

For architecture, component reference, and developer notes, see
[`cost-and-storm-protection-internals.md`](cost-and-storm-protection-internals.md).

## At a glance

| What | Default | How to enable |
|---|---|---|
| Prompt caching | **On** (transparent) | Always active — no opt-in |
| Token-cost metrics | **On** | Always exposed on `:METRICS_PORT/metrics` |
| Severity-based model routing | Off | Set any `CLAUDE_MODEL_<SEVERITY>` env var |
| Severity-based agent rounds | Off | Set any `MAX_AGENT_ROUNDS_<SEVERITY>` env var |
| Group-cooldown | Off | `GROUP_COOLDOWN_SECONDS=60` |
| Storm-mode | Off | `STORM_MODE_THRESHOLD=50` |
| Circuit-breaker | Off | `CIRCUIT_BREAKER_THRESHOLD=5` |

Defaults preserve previous behavior. After upgrading without setting any
opt-in env vars, the only observable change is that Anthropic's prompt-cache
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

Four token counters, all on `:METRICS_PORT/metrics`. Labels:
`{source, severity, model}`. (Severity is recorded as `"all"` because
per-call severity isn't threaded into the API client yet — to be refined.)

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
# that's burning rounds. Enable the circuit-breaker to gate this.
rate(claude_output_tokens_total[5m]) /
  rate(claude_input_tokens_total[5m]) > 0.15
```

## Rollout playbook

Recommended sequence after a fresh deploy. Each step is independently
revertible — just remove the env var and redeploy.

**Cost first** (most operators stop here):

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
5. **Tighten if needed.** If cost is still a concern, consider
   `MAX_AGENT_ROUNDS_WARNING=0` (aggressive setup).

**Then storm robustness**, only if you've seen alert bursts or
Anthropic-API outages cause issues:

6. **Enable group-cooldown** with `GROUP_COOLDOWN_SECONDS=60`. Watch
   `alerts_cooldown_total{source}` rise during deployment thrashes.
7. **Enable circuit-breaker** with `CIRCUIT_BREAKER_THRESHOLD=5`. The
   breaker only fires under sustained Claude-API failure; in normal
   operation `claude_circuit_breaker_state` stays at 0.
8. **Enable storm-mode last** with `STORM_MODE_THRESHOLD=50`. This is the
   loudest behavior change — all severities drop to `rounds=0` while the
   threshold is exceeded. Tune the threshold based on your normal alert
   volume.

See the [Storm Robustness](#storm-robustness) section below for what each
of those features does.

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

## OpenRouter Setup

The `anthropic-sdk-go` migration restored OpenRouter compatibility. To route via OpenRouter:

```sh
export ANTHROPIC_BASE_URL=https://openrouter.ai/api
export ANTHROPIC_AUTH_TOKEN=sk-or-v1-...
unset ANTHROPIC_API_KEY  # only one of API_KEY / AUTH_TOKEN may be set
```

The SDK uses `Authorization: Bearer $ANTHROPIC_AUTH_TOKEN` against this base URL, which is OpenRouter's expected auth shape.

## Storm Robustness

Three opt-in protections against alert bursts and Anthropic-API outages.
They close two attack surfaces that caching and severity routing alone do
not address: high cost from re-analyzing every distinct fingerprint during
a storm, and the Storm-Verstärker-Bug where API failures used to clear
cooldowns and cause Alertmanager to retry into a degraded API.

All three default to disabled (`THRESHOLD=0` / `SECONDS=0`). Enable each
independently after observing the cost-and-cache metrics above.

### Group-Cooldown

Set `GROUP_COOLDOWN_SECONDS=60` (suggested). Both analyzers will treat alerts
with the same group key as a single alert during the TTL window:

- k8s: `groupKey = alertname:namespace`  (empty namespace → `alertname:_cluster_`)
- CheckMK: `groupKey = host:service`     (empty service → `host:_host_`)

Group-cooldown sits next to (not in place of) the existing fingerprint
cooldown. The handler uses the atomic `CooldownManager.CheckAndSetWithGroup`
to set both at once, with rollback if either is already in cooldown.

### Storm-Mode

Set `STORM_MODE_THRESHOLD=50` (alerts/5min, suggested). When the sliding
5-minute window exceeds the threshold, the analyzer enters degraded mode:

- All severities are forced to `rounds=0` (no tool-loop) — saves the most
  cost per alert.
- Group-key remains unchanged (storm mode doesn't widen dedup; that's
  operator policy via `GROUP_COOLDOWN_SECONDS`).
- Aggregated ntfy via the shared `NotifyAggregator`: one summary per
  `STORM_MODE_NOTIFY_INTERVAL` (default 60s) instead of N per-alert messages.

Gauge: `storm_mode_active{source}` (0/1) — page operators on `1` for >5min.

### Circuit-Breaker

Set `CIRCUIT_BREAKER_THRESHOLD=5` (consecutive failures, suggested). When
5 logical analyses in a row fail, the breaker opens for
`CIRCUIT_BREAKER_OPEN_SECONDS` (default 60). All `Acquire()` calls during
that window return `ErrCircuitOpen` — alerts get aggregated into the
breaker-aggregator instead of triggering API calls.

After the open period the breaker enters half-open: exactly one probe
analysis is allowed (with `rounds=0`). On success → closed; on failure →
open again.

A probe-watchdog (`CIRCUIT_BREAKER_MAX_PROBE_SECONDS`, default 60s)
prevents stuck-state if the probe goroutine hangs without calling
`permit.Done()`.

Gauge: `claude_circuit_breaker_state{source}` (0=closed, 1=open, 2=half-open).

### Storm-Verstärker-Bug Mitigation

The pipeline tracks the failure phase (Pre-API / API / Post-API) and the
analysis error in separate variables. Cooldowns are cleared only for
Pre-API and API-phase failures that are NOT `ErrCircuitOpen`. With an
open breaker, cooldowns remain set so Alertmanager-retries hit cooldowns
on subsequent webhooks instead of hammering the degraded API.

### Notify-Aggregator Drop Metric

`notify_aggregator_drops_total{aggregator}` (counter, labels: `storm`,
`breaker`) reports alerts that were dropped because:

- the aggregator's in-channel was full (back-pressure),
- the aggregator was already stopped (post-shutdown), or
- the tick-flush failed to publish (e.g. ntfy unavailable).

Sustained non-zero drops indicate the aggregation interval is too long
for the current alert volume, or the publisher is failing. Aggregate
notifications represent a lower bound on the input stream — the
difference is in this metric.

### Recommended PromQL

```
# Cache-hit rate
sum(rate(claude_cache_read_tokens_total[5m]))
  / sum(rate(claude_cache_read_tokens_total[5m])
       + rate(claude_cache_creation_tokens_total[5m])
       + rate(claude_input_tokens_total[5m]))

# Storm-mode dwell-time (alerts on storm_mode_active=1 for >5min)
storm_mode_active{source="k8s"} == 1

# Breaker-open dwell-time (alerts on state=1 for >2min)
claude_circuit_breaker_state{source="checkmk"} == 1

# Aggregator-drop rate
sum by (aggregator) (rate(notify_aggregator_drops_total[5m]))
```

### Multi-replica caveat

All cooldown, storm-detector, and circuit-breaker state is in-memory and
pod-local. Running multiple replicas (HPA) fragments the mitigations:
Alertmanager-retries can land on different pods and bypass the cooldown,
the storm threshold is per-pod (so the effective storm threshold is
N × THRESHOLD for N replicas), and breaker state is not shared. Operators
with HPA should keep `replicaCount=1` unless absolutely necessary; scale up
only on sustained load.

For component-level architecture and developer notes, see
[`cost-and-storm-protection-internals.md`](cost-and-storm-protection-internals.md).
