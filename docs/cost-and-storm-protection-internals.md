# Storm & Cost Protection — Internals

Architecture and component reference for the cost-and-storm-protection
features: prompt caching, severity-based routing, group-cooldown,
storm-mode, circuit-breaker, and pipeline failure-phase differentiation.

This document covers **architecture, components, configuration, observability,
failure modes, and developer notes**. For the day-to-day operator workflow
(when to enable each knob, rollout sequence, recommended PromQL), see
[`cost-and-storm-protection.md`](cost-and-storm-protection.md).

- **Design spec:** [`superpowers/specs/2026-05-01-storm-cost-protection-design.md`](superpowers/specs/2026-05-01-storm-cost-protection-design.md)

## Table of contents

- [What it solves](#what-it-solves)
- [At a glance](#at-a-glance)
- [Architecture](#architecture)
- [Components](#components)
  - [StormDetector](#stormdetector)
  - [CircuitBreaker (Permit-Token)](#circuitbreaker-permit-token)
  - [NotifyAggregator](#notifyaggregator)
  - [CooldownManager extensions](#cooldownmanager-extensions)
  - [Pipeline phase tracking](#pipeline-phase-tracking)
- [Configuration](#configuration)
- [Metrics](#metrics)
- [Failure-mode runbook](#failure-mode-runbook)
- [Component interaction matrix](#component-interaction-matrix)
- [Developer notes](#developer-notes)
- [Limitations](#limitations)

## What it solves

Two pressure axes against the analyzers:

- **Cost per analysis** — high-severity alerts can use Opus; lower-severity
  alerts can be routed to Haiku or even skip the tool loop entirely. Prompt
  caching reduces token usage on the cached prefix.
- **Load and Anthropic-API failure modes** — distinct fingerprints in a
  burst can each trigger a full analysis (50 crashing pods × 10 tool-rounds
  is expensive); Anthropic outages can cascade if every retry tries the
  broken API again.

The features in this document address both axes: caching and severity
routing optimize the per-analysis cost; group-cooldown deduplicates alerts
that share a coarser key; storm-mode forces cheaper static analysis under
sustained burst load; the circuit-breaker halts API calls during
sustained failures and prevents Alertmanager-retries from amplifying the
problem (the Storm-Verstärker-Bug fix).

Most features are opt-in and default disabled. Caching and the four
token-cost metrics are always on.

## At a glance

| Feature | Knob | Default | Effect when enabled |
|---|---|---|---|
| Group-cooldown | `GROUP_COOLDOWN_SECONDS` | `0` (off) | Coarser dedup: alerts sharing alertname+namespace (k8s) or host+service (checkmk) collapse to one analysis per TTL window |
| Storm-mode | `STORM_MODE_THRESHOLD` | `0` (off) | At >N alerts/5min, all severities are forced to `rounds=0` (no tool loop) and notifications are aggregated |
| Circuit-breaker | `CIRCUIT_BREAKER_THRESHOLD` | `0` (off) | At N consecutive analysis failures, the breaker opens and rejects calls for `OPEN_SECONDS`; one half-open probe per cycle |
| Pipeline phase-tracking | always on | n/a | Cooldowns are kept on `ErrCircuitOpen` and post-API failures (Verstärker-Bug fix) |

## Architecture

```
┌────────────┐    1. POST /webhook
│ Alertmgr / │───────────────────────────────────┐
│  CheckMK   │                                   │
└────────────┘                                   ▼
                                          ┌─────────────────────┐
                                          │   handler           │
                                          │                     │
                                          │   auth check        │
                                          │   parse payload     │
                                          │                     │
                                          │   ┌───────────────┐ │
                                          │   │ CheckAndSet   │ │  fingerprint + group
                                          │   │ WithGroup     │ │  cooldowns (atomic)
                                          │   └─────┬─────────┘ │
                                          │         │ pass      │
                                          │         ▼           │
                                          │   storm.Record()    │
                                          │         │           │
                                          │         ▼           │
                                          │   server.Enqueue ───┼──────► work queue
                                          └─────────────────────┘        (5 workers)
                                                                              │
                                                                              ▼
                                                                       ┌─────────────────────────┐
                                                                       │  pipeline.ProcessAlert  │
                                                                       │                         │
                                                                       │  phase = phasePreAPI    │
                                                                       │  GatherContext(...)     │
                                                                       │                         │
                                                                       │  phase = phaseAPI       │
                                                                       │  permit, err :=         │
                                                                       │    Breaker.Acquire() ───┼──► ErrCircuitOpen?
                                                                       │                         │     yes → BreakerNotify.Add()
                                                                       │  if Storm or Probe:     │     no  → continue
                                                                       │    rounds = 0           │
                                                                       │                         │
                                                                       │  Analyzer.Analyze()  /  │
                                                                       │   RunToolLoop(...)      │
                                                                       │                         │
                                                                       │  phase = phasePostAPI   │
                                                                       │  StormNotify.Add()  /   │
                                                                       │   PublishAll(...)       │
                                                                       │                         │
                                                                       │  defer:                 │
                                                                       │   permit.Done(err)      │
                                                                       │   phase-cleanup         │
                                                                       └─────────────────────────┘
```

The new pieces are all in `internal/shared/`:

- `storm.go` — sliding-window counter
- `breaker.go` — circuit-breaker with permit tokens
- `notify_aggregator.go` — buffered notification emitter
- `cooldown.go` — extended with atomic group-cooldown methods
- `policy.go` — extended with `Storm` pointer + `IsDegraded()`

The k8s and checkmk pipelines call into them; both `cmd/*-analyzer/main.go`
construct the components from env vars at startup.

## Components

### StormDetector

A sliding-window counter (`internal/shared/storm.go`) that tracks how many
new alerts entered the system in the last 5 minutes. The window has 5
buckets of 1 minute each.

```go
type StormDetector struct {
    threshold int
    now       func() time.Time   // injectable for tests
    mu        sync.Mutex
    buckets   [5]bucket
}

func NewStormDetector(threshold int, now func() time.Time) *StormDetector
func (d *StormDetector) Record()
func (d *StormDetector) Count() int
func (d *StormDetector) Threshold() int
```

**Disabled-as-nil pattern:** `NewStormDetector(threshold<=0, _)` returns
`nil`. All methods are nil-safe. The pipeline never has to special-case
"storm-mode off".

**Where Record() is called:** in the handler, **after** the cooldown check,
**before** enqueue. This way the detector counts incoming pressure (real
new alerts), not successful enqueues — even if the queue is full and we're
returning 503s, storm-mode still triggers.

**Where Count() is read:** by `AnalysisPolicy.IsDegraded()` from inside the
pipeline, on every alert. The pipeline forces `rounds=0` when `IsDegraded()`
returns true.

### CircuitBreaker (Permit-Token)

A three-state breaker (`internal/shared/breaker.go`) gated at the
**logical-call level** — one analysis attempt is one Acquire/Done cycle,
regardless of how many HTTP roundtrips the analysis does internally.

```go
type CircuitBreaker struct {
    threshold        int
    openDuration     time.Duration
    maxProbeDuration time.Duration   // probe-watchdog timeout
    now              func() time.Time
    mu               sync.Mutex
    state            breakerState
    consecFailures   int
    openedAt         time.Time
    probeStartedAt   time.Time
    halfOpenInFlight bool
}

type Permit struct { /* ... */ }

func NewCircuitBreaker(threshold int, openDuration, maxProbeDuration time.Duration, now func() time.Time) *CircuitBreaker
func (b *CircuitBreaker) Acquire() (*Permit, error)        // ErrCircuitOpen on rejection
func (b *CircuitBreaker) State() int                       // 0=closed, 1=open, 2=half-open

func (p *Permit) IsProbe() bool
func (p *Permit) Done(err error)                           // idempotent
```

**Why a permit token instead of `BeforeCall`/`RecordResult`?** Spec section
2.3 documents the rationale: a separate before/after pair has two structural
problems —

1. **Probe-correlation is global, not call-local.** Without a per-call
   token, `IsHalfOpenProbe()` returns global state, not the state of the
   specific caller who acquired.
2. **Panic-cleanup.** A panic between `BeforeCall()=nil` and the missing
   `RecordResult()` leaks `halfOpenInFlight=true` forever.

The permit pattern solves both: `permit.IsProbe()` is call-local, and
`defer permit.Done(err)` ensures cleanup even on panic.

**Probe-watchdog:** if a half-open probe takes longer than
`maxProbeDuration` (e.g. probe goroutine hung on a slow Claude call), the
next `Acquire()` resets `halfOpenInFlight=false` and treats the probe as
failed (`state=open`, `openedAt=now`). Without the watchdog, a stuck probe
would block all callers until pod restart.

**Disabled-as-nil:** `NewCircuitBreaker(threshold<=0, …)` returns `nil`.
`Acquire()` on nil returns a no-op permit.

### NotifyAggregator

A single-owner-goroutine buffer (`internal/shared/notify_aggregator.go`)
that collapses many alert notifications into one summary per interval.
Used by the pipeline when the breaker is open (BreakerNotify) or when
storm-mode is active (StormNotify).

```go
type NotifyAggregator struct {
    publishers []Publisher
    interval   time.Duration
    titleFmt   string
    priority   string
    drops      prometheus.Counter

    in       chan string
    stopReq  chan stopRequest
    stopOnce sync.Once
    stopped  chan struct{}
    stopErr  error
    stopping atomic.Bool
}

func NewNotifyAggregator(publishers []Publisher, interval time.Duration, titleFmt, priority string, drops prometheus.Counter) *NotifyAggregator
func (a *NotifyAggregator) Add(alertTitle string) bool
func (a *NotifyAggregator) Stop(ctx context.Context) error
```

**Concurrency model:** the owner goroutine is the **only** writer to the
buffer. `Add()` and `Stop()` communicate via channels — no shared-memory
mutation. This eliminates the mutex+timer race that the initial design
had (see spec Round-2 review notes).

**Add() back-pressure:** non-blocking. If the in-channel is at capacity,
the alert is dropped and the drops counter increments. This keeps
webhook-handler latency bounded under storm bursts.

**Stop() protocol:** request-reply via `stopRequest{ctx, ack}`. First
caller's `sync.Once.Do` sends the request; later callers wait on
`<-a.stopped`. The owner drains the in-channel with a rolling 10ms deadline
(absorbs in-flight Add() goroutines), then flushes with the caller-supplied
ctx, then sends ack and exits. Final flush uses **caller ctx, not
`context.Background()`** — a hung publisher cannot leak the goroutine.

**Drops are observable:** every dropped alert (channel-full,
post-stop, race against stop, publish-error) increments
`notify_aggregator_drops_total{aggregator="…"}`. Sustained non-zero
drops mean the aggregation interval is too long for the load, or the
publisher is failing.

### CooldownManager extensions

`internal/shared/cooldown.go` gains three methods around an additional
group-cooldown map:

```go
func (cm *CooldownManager) CheckAndSetGroup(groupKey string, ttl time.Duration) bool
func (cm *CooldownManager) ClearGroup(groupKey string)
func (cm *CooldownManager) CheckAndSetWithGroup(
    fingerprint string, fpTTL time.Duration,
    groupKey string, groupTTL time.Duration,
) bool
```

`CheckAndSetWithGroup` is the **default path used by handlers**. It
guarantees:

- **Atomic semantics:** either both cooldowns are set, or neither.
- **Rollback on fingerprint-block:** if the group is free but the
  fingerprint is already in cooldown, the group entry is rolled back
  before returning false. No orphan group entries.
- **Lock hierarchy:** `groupMu` is acquired before `fpMu`, both are held
  over the entire decision. No other method takes them in reverse order →
  no deadlock.
- **Empty-group fast path:** if `groupKey == ""` or `groupTTL == 0`, the
  group is skipped and the call reduces to a plain fingerprint check.

**Group-key derivation** lives in the handlers (it's source-specific):

| Source | Group key | Empty-value fallback |
|---|---|---|
| k8s (`internal/k8s/handler.go`) | `alertname:namespace` | `alertname:_cluster_` |
| checkmk (`internal/checkmk/handler.go`) | `host:service` | `host:_host_` |

The sentinel suffixes (`_cluster_`, `_host_`) prevent two distinct alerts
both with empty namespace/service from collapsing into the same group.

### Pipeline phase tracking

The pipeline orchestration is shared: `shared.ProcessAlert`
(`internal/shared/pipeline.go`) owns the phase state machine, breaker-permit
settlement, and cooldown cleanup for both products; `internal/k8s/pipeline.go`
and `internal/checkmk/pipeline.go` only supply product hooks (context
gathering, prompt construction, the static-vs-agentic decision, notification
naming) via the `shared.PipelineHooks` interface. It uses a `failurePhase`
enum and a separate `analysisErr` variable — **not the named return** — so
that cleanup decisions cannot be flipped by a later post-API error.

```go
type failurePhase int

const (
    phasePreAPI failurePhase = iota
    phaseAPI
    phasePostAPI
)

func ProcessAlert(ctx context.Context, deps PipelineDeps, hooks PipelineHooks, alert AlertPayload) {
    var (
        phase       = phasePreAPI
        analysisErr error
        permit      *Permit
    )

    // Cleanup defer reads phase + analysisErr (NOT the named return).
    defer func() {
        if r := recover(); r != nil {
            if analysisErr == nil {
                analysisErr = fmt.Errorf("panic recovered: %v", r)
            }
            defer panic(r)            // re-panic AFTER cleanup
        }
        if permit != nil {
            permit.Done(analysisErr)  // FIRST so the breaker sees panics + late errors
        }
        switch phase {
        case phasePreAPI:
            // clear cooldowns, AlertsFailed++
        case phaseAPI:
            if analysisErr == nil { return }
            if errors.Is(analysisErr, ErrCircuitOpen) {
                // Verstärker-Mitigation: KEEP cooldowns
                return
            }
            // clear cooldowns, AlertsFailed++
        case phasePostAPI:
            // analysis succeeded; ntfy-failure logged separately, KEEP cooldowns
            return
        }
    }()

    // ... pipeline body, sets phase + analysisErr along the way ...
}
```

**Why two variables (`phase` + `analysisErr`) instead of just `err`?**
The cleanup decision is "did the analysis fail and was it not
ErrCircuitOpen?". Reading the named return would conflate the analysis
error with a later `PublishAll` error from the post-API path —
publish-failure on a successful analysis would (incorrectly) clear the
cooldown. With a separate `analysisErr` only set in the API phase, the
defer's switch is unambiguous.

**Why `permit.Done()` runs INSIDE the cleanup defer?** Because deferred
calls run LIFO. If `defer permit.Done(analysisErr)` is registered separately,
it runs FIRST during a panic — at which point `analysisErr` is still nil
and the breaker would record a SUCCESS for the panicked analysis. Folding
`Done()` into the cleanup defer body (after `recover()`) ensures the
breaker observes panics correctly. Regression test:
`TestProcessAlert_AnalyzerPanicOpensBreaker` in both pipelines.

## Configuration

All storm-robustness environment variables are optional and default disabled.
Validated at startup via `shared.ParseIntEnv` — out-of-range values cause
a hard exit with a clear message.

```
GROUP_COOLDOWN_SECONDS         (int, 0–86400)   default: 0    (suggested: 60)
STORM_MODE_THRESHOLD           (int, 0–100000)  default: 0    (suggested: 50)
STORM_MODE_NOTIFY_INTERVAL     (duration)       default: 60s
CIRCUIT_BREAKER_THRESHOLD      (int, 0–100)     default: 0    (suggested: 5)
CIRCUIT_BREAKER_OPEN_SECONDS   (int, 1–3600)    default: 60
CIRCUIT_BREAKER_MAX_PROBE_SECONDS (int, 1–3600) default: 60
CIRCUIT_BREAKER_NOTIFY_INTERVAL (duration)      default: 300s
```

The "suggested" values are starting points — see
[`cost-and-storm-protection.md`](cost-and-storm-protection.md) for the
recommended migration sequence.

## Metrics

Three new metrics on the existing `:METRICS_PORT/metrics` endpoint:

| Metric | Type | Labels | Notes |
|---|---|---|---|
| `storm_mode_active` | Gauge | `source` | 0/1 — 1 when `policy.IsDegraded()` |
| `claude_circuit_breaker_state` | Gauge | `source` | 0=closed, 1=open, 2=half-open |
| `notify_aggregator_drops_total` | Counter | `aggregator` | `aggregator="storm"\|"breaker"` |

Both gauges are refreshed on every alert (set in the pipeline before
`Acquire()`). The counter increments inside `Add()` for channel-full /
post-stop / race drops, and inside the owner goroutine for
publish-error drops.

## Failure-mode runbook

| Symptom | Likely cause | Where to look |
|---|---|---|
| `claude_circuit_breaker_state == 1` for >2min | Sustained Claude API failures | Anthropic status page, `claude_api_errors_total`, `claude_api_duration_seconds` p95 |
| `claude_circuit_breaker_state == 2` flapping | Probe failures: half-open → open immediately | Last successful probe in logs; check Anthropic auth and rate-limit headers |
| `storm_mode_active == 1` for >5min | Real alert burst from one source | k8s deployment thrashing, mass node failure, etc. — operator-triage |
| `notify_aggregator_drops_total{aggregator="storm"}` rising | Storm exceeding aggregator buffer | Lower `STORM_MODE_NOTIFY_INTERVAL` or accept the drops as "known incident" |
| `notify_aggregator_drops_total{aggregator="breaker"}` rising | Many alerts during breaker-open | Expected during outages; Grafana annotation, no action |
| `alerts_cooldown_total` low under storm | Group-cooldown not enabled | Set `GROUP_COOLDOWN_SECONDS=60` |
| Webhook returns 503, `alerts_queue_full_total` rising | Worker saturation; storm threshold may not be triggering | Verify `STORM_MODE_THRESHOLD` is set; check `storm_mode_active` |

Two named bugs the design explicitly mitigates:

- **Storm-Verstärker-Bug** — pre-Phase-2, an API failure cleared cooldowns
  and Alertmanager retries hammered the broken API. Now: `phaseAPI` +
  `ErrCircuitOpen` keeps cooldowns. **Test:** `TestVerstaerkerBug_OpenBreakerKeepsCooldown_NoSecondAnalysis`
  in both pipeline test files.
- **Half-open-probe-stuck** — a slow Claude call inside a probe could
  block the breaker indefinitely. Now: probe-watchdog auto-fails after
  `maxProbeDuration`. **Test:** `TestCircuitBreaker_ProbeWatchdogReleasesStuckProbe`.

## Component interaction matrix

When multiple features are simultaneously active:

| Storm | Breaker | Behavior | Notification |
|---|---|---|---|
| no | closed | Normal API call with configured rounds | Per-alert ntfy |
| no | open | No API call, `ErrCircuitOpen`, cooldowns kept | Breaker-aggregator |
| no | half-open | One probe with `rounds=0`, others get `ErrCircuitOpen` | Breaker-aggregator |
| yes | closed | `Analyze`-only (`rounds=0`), storm-degraded | Storm-aggregator |
| yes | open | No API call, cooldowns kept | Breaker-aggregator (priority) |
| yes | half-open | Probe with `rounds=0`, all others rejected | Breaker-aggregator |

**Breaker dominates Storm** for the call-permission decision. Both gauges
are simultaneously visible in Grafana — operators see "the system is in
storm-mode AND the breaker is open" as two correlated signals.

## Developer notes

### When to nil-check vs trust nil-safe

The storm-robustness components are **all nil-safe**. The pipeline never
needs an `if breaker != nil` guard around `Acquire()` — a nil breaker
returns a no-op permit. Same for `Storm.Record()`, `StormNotify.Add()`,
`policy.IsDegraded()`. Code that constructs the components decides
disabled-vs-enabled by passing `0` for the threshold/interval; everything
downstream is uniform.

### The Permit-Token contract

`Acquire()` and `Done()` are correlated by the `*Permit` token. The
contract:

1. Every successful `Acquire()` MUST be followed by a `Done()`.
2. `Done()` is idempotent — multiple calls are safe but only the first
   has effect.
3. `permit.Done()` should run AFTER any `recover()` that captures a
   panic into `analysisErr`, so the breaker observes panics as
   failures. Pattern: fold `permit.Done()` into the cleanup defer body,
   not a separate defer.

Violations in code review: a separate `defer permit.Done(analysisErr)`
is a red flag. Either it runs before `recover()` (LIFO ordering) or it
captures `analysisErr` at registration time (closure semantics) — both
are bugs the original spec didn't catch and the implementation review
flagged.

### Lock hierarchy in CooldownManager

```
groupMu  <  fpMu
```

`CheckAndSetWithGroup` is the only method that holds both. Order:
acquire `groupMu`, then `fpMu`, release in reverse via deferred unlock.
**Do not add a method that takes them in reverse order** — that would
introduce a deadlock-cycle. If you need a method that mutates only one
map, use `CheckAndSet` / `CheckAndSetGroup` / `Clear` / `ClearGroup`.

### Tests that lock down invariants

If you change the storm-protection internals, make sure these still pass
under `-race`:

- `TestVerstaerkerBug_OpenBreakerKeepsCooldown_NoSecondAnalysis` (both pipelines) —
  cooldowns survive an open breaker; Claude is not called on retries.
- `TestProcessAlert_HalfOpenProbeForcesRoundsZero` (both pipelines) —
  half-open probe forces `rounds=0`, no tool loop.
- `TestProcessAlert_StormDegradedForcesRoundsZero` (both pipelines) —
  storm-degraded forces `rounds=0`.
- `TestProcessAlert_AnalyzerPanicOpensBreaker` (k8s) — panic during
  analysis trips the breaker.
- `TestProcessAlert_AnalyzerErrorOpensBreaker` (both pipelines) — error
  during analysis trips the breaker.
- `TestCircuitBreaker_ProbeWatchdogReleasesStuckProbe` — stuck probe is
  auto-released after `maxProbeDuration`.
- `TestCircuitBreaker_ConcurrentHalfOpenAcquireGivesOnlyOneProbe` — under
  contention, exactly one probe permit is granted.
- `TestCooldownManager_CheckAndSetWithGroup_*` (5 tests) — atomicity,
  rollback, empty-group fast path, concurrent winner-selection.
- `TestNotifyAggregator_StopRaceNoLosses` — 1000 parallel Add() against
  a Stop, `published+drops == 1000` (no silent loss).
- `TestNotifyAggregator_StopConcurrentCallersAgree` — 50 parallel
  Stop() callers must agree on the result.
- `TestNotifyAggregator_HungPublisher_StopReturnsTimeout` — hung
  publisher does not leak the owner goroutine.

### The closure-vs-direct-arg anti-pattern

```go
// WRONG — analysisErr is evaluated at defer-registration time (always nil here)
defer permit.Done(analysisErr)

// CORRECT — closure reads analysisErr at execution time
defer func() { permit.Done(analysisErr) }()

// CURRENT — folded into the cleanup defer for correct panic ordering
defer func() {
    if r := recover(); r != nil { /* set analysisErr */ defer panic(r) }
    if permit != nil { permit.Done(analysisErr) }
    /* phase-switch cleanup */
}()
```

The current implementation is the third form because the first two have
distinct bugs (the first ignores the analysis error entirely; the second
records SUCCESS for panicked analyses).

## Limitations

The storm-robustness features are intentionally narrow. Out-of-scope:

- **Hard kill-switch / spend cap.** Anthropic's workspace spend limit is
  the external backstop. We don't track per-day cost.
- **Persistent state.** Cooldowns, storm-counter, breaker state are all
  pod-local in-memory. A pod restart resets everything.
- **Multi-replica consistency.** Every replica has its own cooldown map,
  storm window, and breaker state. Alertmanager retries can land on a
  different pod and bypass the cooldown set on the first pod. **Operators
  with HPA should keep `replicaCount=1` unless absolutely necessary.**
  Scale up only on sustained load. The mitigation is documented as the
  explicit Wirksamkeitsgrenze ("effectiveness boundary") of the design.
- **Dynamic config reloads.** All thresholds are read at startup from env
  vars. Changing them requires a pod restart.
- **Per-source notification customization.** Storm and breaker
  notification format is hard-coded; if the operator wants different
  templates per source, they'd need to extend `NotifyAggregator`.

For each of these, the cost and storm-robustness metrics give operators the
visibility to decide whether the limitation is acceptable in their
deployment.
