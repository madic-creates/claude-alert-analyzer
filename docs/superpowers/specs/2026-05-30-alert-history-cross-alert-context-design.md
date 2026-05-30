# Alert History / Cross-Alert Context for Repeated Fingerprints

**Date:** 2026-05-30
**Status:** Approved (revised after codebase review)
**Issue:** [#24](https://github.com/madic-creates/claude-alert-analyzer/issues/24)

## Summary

Today every alert is analyzed in complete isolation. If the same fingerprint fires
repeatedly, Claude restarts from scratch each time — no awareness that this is a
recurring incident and no recollection of what the previous analysis concluded.

This feature maintains a small **persistent** per-fingerprint history (SQLite on a
PVC) and feeds two kinds of cross-alert context into the Claude prompt on a re-fire:

- **Recurrence metadata** — "this fingerprint has fired 3 times in the last 6h"
  (Phase A, cheap, no secret/anchoring risk).
- **Prior hypotheses** — the one-line `SUMMARY:` of the last N analyses, explicitly
  framed as hypotheses to verify, not facts (Phase B, layered on top of A).

The feature is **best-effort and never blocking**: any history-store error is logged
and counted as a metric, and the analysis proceeds exactly as it does today. It is
**default-disabled** (`HISTORY_ENABLED=false`). It applies to **both** analyzers
(k8s + checkmk); the core lives in `internal/shared/`.

> **Revision note.** A codebase review corrected the original draft's central
> assumption that the cooldown gate lives in `ProcessAlert`. It does not — the gate is
> in the HTTP handler, and analysis runs on a worker behind a channel. The write path,
> the "eventID threading", and several deployment/prompt claims were redesigned around
> that handler/worker boundary. See §2 and the Design Decisions below.

## Design Decisions (from brainstorming + review)

1. **Staged scope (A then B).** Phase A (recurrence metadata) is the foundation;
   Phase B (prior-hypothesis injection) layers on top behind a separate flag.
2. **Persistence: SQLite on a PVC** (`modernc.org/sqlite`, CGO-free — the build is
   `CGO_ENABLED=0`, so a CGO driver like `mattn/go-sqlite3` would not compile). Not
   in-memory — the headline benefit ("Nth time this week") lives on the hours/days
   timescale, exactly where pod restarts would wipe an in-memory store.
3. **Stored summary = a structured one-line `SUMMARY:`** emitted by Claude itself.
   No separate summarization call (YAGNI), no full-text injection (anchoring + prompt
   cost). A full-text column is reserved for future audit but is **not** injected.
4. **Count all fires, not just analyses** — including cooldown-suppressed ones, which
   forces the fire-record to be written in the **HTTP handler before the cooldown
   gate** (the worker never sees suppressed fires). See §2.
5. **Two-row model, no eventID threading.** Because the fire-record (handler) and the
   summary-record (worker) are separated by the work-queue channel, threading a row id
   across that boundary is brittle. Instead each occurrence may produce up to two rows
   distinguished by a `kind` column (`fire` | `analysis`). Count = `kind='fire'`;
   prior hypotheses = `kind='analysis'`. No double counting, no id plumbing.
6. **Async single-writer.** All writes go through one background goroutine over a
   buffered channel, so the latency-sensitive webhook path only does a non-blocking
   channel send (Alertmanager batches up to 100 alerts/request). This also gives SQLite
   a natural single writer. Reads (`Lookup`) run synchronously on the worker side.
7. **Both analyzers** (k8s + checkmk).

### Resolved judgment calls

- **Queue-full fires are counted.** With the fire-record placed before the cooldown
  gate, a fire that later can't enqueue (full work queue) has already been counted. A
  fire that fired is a fire — the recurrence count stays honest. (This reverses the
  original draft's "not counted" note, which was incompatible with counting before the
  cooldown gate.)
- **Async writer, best-effort drop.** If the write channel is full, the record is
  dropped and a drop metric is incremented; analysis is never affected.
- `journal_mode=DELETE` (rollback journal), not WAL — WAL relies on shared-memory mmap
  and locking semantics that are unreliable on network-backed PVCs, and the single
  writer goroutine makes WAL's concurrency benefit moot. `temp_store=MEMORY` because the
  k8s binary runs on `scratch` with `readOnlyRootFilesystem: true` (no `/tmp`).
- `SetMaxOpenConns(1)` — one connection, `database/sql` serializes all access; pairs
  with the single-writer model.
- The `SUMMARY:` marker line is **stripped from the ntfy notification** (machine
  marker, not user-facing noise).
- A single `HISTORY_TTL` governs both the count window and pruning (no separate
  retention knob). "This week" = set `HISTORY_TTL=168h`.
- Single-replica remains mandatory (RWO PVC + SQLite). Multi-replica would need an
  external store — documented as future work, not built.

## Data Flow

The cooldown gate, enqueue, and queue-full drop all live in the **HTTP handler**
(`internal/k8s/handler.go`, `internal/checkmk/handler.go`). Analysis runs on a
**worker** goroutine in `ProcessAlert`, dequeued from the work-queue channel. The
history hooks straddle that boundary:

```
HANDLER (HTTP request goroutine)
  Webhook → Auth → for each alert:
    │
    ├─ RecordFire(fingerprint, severity)        # NON-BLOCKING send to write channel
    │                                           # BEFORE the cooldown gate → counts
    │                                           # suppressed + queue-full fires too
    ├─ cooldown.CheckAndSetWithGroup(...)
    │     └─ suppressed → skip enqueue (fire already counted)
    └─ enqueue(payload) → [work queue channel] (drop if full; fire already counted)

WORKER (ProcessAlert)
    │
    ├─ Lookup(fingerprint, HISTORY_TTL, MAX_ENTRIES) → HistoryView   # synchronous read
    │     └─ if Count > 1: prepend "Alert Recurrence" ContextSection
    │            (+ "Prior analyses" sub-block iff HISTORY_INJECT_PRIOR)
    │
    ├─ GatherContext() → AnalysisContext (with injected history section)
    │
    ├─ Analyze() | RunAgenticDiagnostics()  → analysis text (ends with "SUMMARY: …")
    │
    ├─ ParseSummary(analysis) → (summary, body)
    │     └─ RecordAnalysis(fingerprint, RedactSecrets(summary))   # NON-BLOCKING send
    │
    └─ PublishAll(body)        # SUMMARY: line stripped from published text

WRITER GOROUTINE (single, owns the DB)
    drains write channel → INSERT kind='fire' | kind='analysis'
                         → opportunistic prune (ts < now - HISTORY_TTL)
```

`Count` is read on the worker after the fire was recorded in the handler, so it
includes the current occurrence — "this is the 3rd time" reads naturally. (There is a
benign race: if the writer goroutine hasn't drained the current fire yet, `Count` may
momentarily lag by one. Acceptable for best-effort context.) Prior summaries
(`kind='analysis'`) never include the current occurrence, which hasn't been analyzed
yet.

## Design

### 1. Storage layer (`internal/shared/history.go`)

One interface, two implementations. The pipeline/handler always call the interface;
when disabled, a no-op store keeps the hot paths branch-free and never touches disk.

```go
type HistoryStore interface {
    // RecordFire enqueues a fire event (kind='fire'). Non-blocking; drops on a full
    // channel. Called from the HTTP handler before the cooldown gate.
    RecordFire(ctx context.Context, fingerprint string, sev Severity)
    // RecordAnalysis enqueues an analysis event (kind='analysis') with the already-
    // redacted summary. Non-blocking; drops on a full channel. Called from the worker.
    RecordAnalysis(ctx context.Context, fingerprint string, sev Severity, summary string)
    // Lookup returns recurrence info + the last maxEntries analyzed summaries within
    // the window, newest first. Synchronous read.
    Lookup(ctx context.Context, fingerprint string, window time.Duration, maxEntries int) HistoryView
    // Close stops the writer goroutine, drains pending writes, and closes the DB.
    Close() error
}

type HistoryView struct {
    Count     int            // kind='fire' rows within the window (incl. current fire)
    FirstSeen time.Time
    LastSeen  time.Time
    Prior     []PriorFinding // kind='analysis' rows, newest first
}

type PriorFinding struct {
    At       time.Time
    Summary  string
    Severity Severity
}
```

`RecordFire`/`RecordAnalysis` return nothing — they are fire-and-forget sends, and
errors surface as drop/error metrics, not return values (best-effort contract). `Lookup`
returns a value (not an error); on a query error it logs, bumps the error metric, and
returns a zero `HistoryView`.

- `sqliteHistoryStore` — `database/sql` + `modernc.org/sqlite`, opened with
  `_pragma=journal_mode(DELETE)`, `_pragma=temp_store(MEMORY)`, `_pragma=busy_timeout(2000)`.
  `db.SetMaxOpenConns(1)`. A buffered `chan writeOp` (cap e.g. 256) and one writer
  goroutine started in the constructor; `Close` signals it to drain and exit. Schema
  created on open via `CREATE TABLE IF NOT EXISTS`. The DB directory is created
  (`os.MkdirAll`) on open if missing.
- `nopHistoryStore` — every method is a no-op; `Lookup` returns a zero `HistoryView`.
  Constructed when `HISTORY_ENABLED=false`.

Constructor: `NewHistoryStore(cfg BaseConfig, product Product, m AlertMetrics) (HistoryStore, error)`.
With `HISTORY_ENABLED=false` it returns `nopHistoryStore` and never errors. With it
true, an open/DDL failure is returned (fatal at startup — the operator asked for it).

#### Schema

```sql
CREATE TABLE IF NOT EXISTS alert_events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  fingerprint TEXT    NOT NULL,
  ts          INTEGER NOT NULL,   -- unix seconds
  kind        TEXT    NOT NULL,   -- 'fire' | 'analysis'
  severity    TEXT    NOT NULL,
  summary     TEXT,               -- non-NULL only for kind='analysis'
  product     TEXT    NOT NULL    -- "k8s" | "checkmk"
);
CREATE INDEX IF NOT EXISTS idx_events_fp_ts ON alert_events(fingerprint, ts);
```

#### Queries

- Fire write: `INSERT INTO alert_events(fingerprint, ts, kind, severity, summary, product)
  VALUES (?, ?, 'fire', ?, NULL, ?)`.
- Analysis write: `INSERT ... VALUES (?, ?, 'analysis', ?, ?, ?)`.
- Prune (after each write batch): `DELETE FROM alert_events WHERE ts < ?`.
- `Lookup` aggregate: `SELECT COUNT(*), MIN(ts), MAX(ts) FROM alert_events
  WHERE fingerprint=? AND kind='fire' AND ts >= ?`.
- `Lookup` priors: `SELECT ts, summary, severity FROM alert_events
  WHERE fingerprint=? AND kind='analysis' AND ts >= ? ORDER BY ts DESC LIMIT ?`.

### 2. Write paths

**Fire — in the HTTP handler, before the cooldown gate.** In both
`internal/k8s/handler.go` (before `cooldown.CheckAndSetWithGroup`, ~line 115) and
`internal/checkmk/handler.go` (before line 101):

```go
history.RecordFire(ctx, fingerprint, severity)
```

This counts every authenticated fire, including cooldown-suppressed and queue-full
ones. The handler dependency set gains a `HistoryStore` (passed in like `cooldown` and
`enqueue` are today). Because the call is a non-blocking channel send, it adds
negligible latency to the webhook response even for 100-alert batches.

**Analysis — in the worker, after a successful analysis.** In both
`internal/k8s/pipeline.go` and `internal/checkmk/pipeline.go`, after the analysis text
is produced and parsed:

```go
deps.History.RecordAnalysis(ctx, alert.Fingerprint, alert.SeverityLevel, shared.RedactSecrets(summary))
```

- Cooldown-suppressed → the worker never runs → no analysis row (fire row already
  exists). Correct.
- Analysis error → no analysis row (only write on success). The deferred
  cooldown-cleanup machinery (`phase`/`analysisErr`, the "Verstärker-Bug" fix) is
  untouched: history calls never return errors into the pipeline and never participate
  in the named-return / deferred-cleanup logic.

`HistoryStore` is added to each pipeline's `PipelineDeps` as a `shared.HistoryStore`
field, consistent with how `Analyzer`, `Cooldown`, `Metrics`, and `Policy` are wired
(all `shared.*` types). It is also added to the startup nil-checks in `cmd/*/main.go`;
the `nopHistoryStore` guarantees the field is never nil even when disabled.

### 3. Read path & prompt injection

In `ProcessAlert`, before building the prompt from `actx`:

```go
view := deps.History.Lookup(ctx, alert.Fingerprint, cfg.HistoryTTL, cfg.HistoryMaxEntries)
if view.Count > 1 {
    actx.Sections = append([]ContextSection{historySection(view, cfg.HistoryInjectPrior)}, actx.Sections...)
}
```

`historySection` returns a `ContextSection{Name: "Alert Recurrence", Content: ...}` —
it does **not** embed the `## ` heading itself, because `AnalysisContext.FormatForPrompt`
(`internal/shared/payload.go:18-28`) already prefixes each section with `## <Name>\n`.
The rendered Content is:

```
This fingerprint has fired 3 times in the last 6h (first 08:12, last 14:05).

### Prior analyses — treat as hypotheses to verify, not established facts
- 14:05 (warning): OOMKill, likely memory leak in payments-service
- 11:30 (warning): OOMKill after deploy v1.2.3
```

- The recurrence line always renders when `Count > 1`.
- The `### Prior analyses` sub-block renders only when `HistoryInjectPrior` is true
  (Phase B) **and** `view.Prior` is non-empty.
- The "treat as hypotheses to verify, not established facts" framing is the deliberate
  **anchoring mitigation** — keep this wording.
- First occurrence (`Count == 1`) injects nothing (no noise, no extra tokens).

**Ordering note:** the k8s pipeline prepends a fixed `## Alert: …` block *before*
`actx.FormatForPrompt()` (`pipeline.go:132`), so the recurrence section appears just
after the alert header, not at the very document top — acceptable. The checkmk pipeline
appends an SSH-availability note *after* `FormatForPrompt()` (`pipeline.go:153`);
prepending into `actx.Sections` keeps the recurrence block ahead of it.

**Prompt-caching note:** the section is injected into the user message, which already
sits outside the system-prompt / tools-tail / last-`tool_result` cache breakpoints
(`internal/shared/claude.go:53,179-180`). It shifts only per-request user content and
does not break caching.

### 4. SUMMARY line (Phase B)

There are **four** system prompts to update (two static, two agentic templates):

- `internal/k8s/agent.go:306` (`StaticAnalysisSystemPrompt`) and
  `internal/k8s/agent.go:271` (`agentSystemPromptTemplate`)
- `internal/checkmk/agent.go:57` (`StaticAnalysisSystemPrompt`) and
  `internal/checkmk/agent.go:21` (`agentSystemPromptTemplate`)

Each gains a closing instruction:

> End your response with a single line in exactly this form:
> `SUMMARY: <one concise sentence naming the single most likely root cause>`

The agentic templates are `fmt.Sprintf` format strings (`agentSystemPromptForRounds`,
k8s:297 / checkmk:50) — any literal `%` in added text must be escaped as `%%`.

**Surviving the tool loop.** `RunToolLoop` returns only the final assistant turn's text
(`internal/shared/claude.go:197-242`). On the **max-rounds path**, that text comes from
`runForcedSummary` with a hardcoded prompt (`claude.go:238`) that does not currently
restate the SUMMARY requirement. To make the marker reliable, the forced-summary prompt
must also instruct the closing `SUMMARY:` line. A SUMMARY line emitted in an
*intermediate* tool-use turn is discarded by design (only the final turn's text is
returned) — acceptable, since the final turn restates it.

`ParseSummary(text string) (summary, body string)`:

- Finds the last line matching `^SUMMARY:\s*(.+)$`, returns it as `summary` and `body`
  = the text with that line removed (stripped from the ntfy notification).
- **Fallback when absent:** scan for the first non-empty line that is *not* a Markdown
  heading (does not start with `#`), truncate to ~200 chars, use as `summary`; `body`
  unchanged. If no such line exists, store **no** analysis row (better an empty history
  than a misleading "## Root cause" heading as a stored hypothesis).

Publish path uses `body`; storage path stores `RedactSecrets(summary)`.

### 5. Redaction

`RecordAnalysis` is always called with `RedactSecrets(summary)`. The analysis text is
not redacted anywhere today (returned from Claude and published as-is); persisting it to
disk is a new exposure surface, closed here at the single storage call.

### 6. Pruning & cardinality

The writer goroutine runs `DELETE FROM alert_events WHERE ts < (now - HISTORY_TTL)`
opportunistically (e.g. once per N drained writes, or on a coarse timer derived from
write activity — never via wall-clock timers that would complicate testing). This bounds
DB size to roughly `fire_rate × HISTORY_TTL`. No separate retention parameter (YAGNI),
no explicit row cap; revisit only if a real high-cardinality deployment appears.

### 7. Configuration

Env vars are parsed **per binary in `cmd/*/main.go`** (the existing pattern — there is no
shared env loader; `BaseConfig` in `internal/shared/payload.go:50-59` is a plain DTO
populated by each package's `Config.BaseConfig()` method). `time.Duration` env vars have
precedent (`KUBE_API_TIMEOUT`, `CHECKMK_API_TIMEOUT` via inline `time.ParseDuration`).

Add the `HISTORY_*` fields to `BaseConfig`, parse them in each `main.go`, and surface
them via each package's `BaseConfig()` method (mirroring how the storm-robustness knobs
are loaded). Add a `ParseDurationEnv(key string, def time.Duration) time.Duration`
helper to `internal/shared/config.go` alongside the existing `ParseIntEnv` /
`ParseBoolEnv` / `EnvOrDefault` / `RequireEnv`.

| Env var | Default | Meaning |
|---|---|---|
| `HISTORY_ENABLED` | `false` | Master switch. False ⇒ `nopHistoryStore`. |
| `HISTORY_DB_PATH` | `/var/lib/analyzer/history.db` | SQLite file path (on the PVC). |
| `HISTORY_TTL` | `6h` | Lookback window for the recurrence count **and** the prune horizon. |
| `HISTORY_MAX_ENTRIES` | `5` | Max prior hypotheses injected into the prompt. |
| `HISTORY_INJECT_PRIOR` | `true` | Phase-B switch: inject prior summaries. False ⇒ recurrence metadata only (Phase A). |

A/B staging collapses to two flags: Phase A = `HISTORY_ENABLED=true, HISTORY_INJECT_PRIOR=false`;
Phase B = additionally `HISTORY_INJECT_PRIOR=true`.

### 8. Deployment

**k8s-analyzer** (`deploy/k8s-analyzer/deployment.yaml`) — already `replicas: 1`,
`strategy: Recreate`, `runAsNonRoot`/`fsGroup: 65534`, `readOnlyRootFilesystem: true`,
`envFrom` secretRef. Add:

- A `PersistentVolumeClaim` (~100Mi, `ReadWriteOnce`) + volume + `volumeMount` at
  `/var/lib/analyzer`. `fsGroup` already lets the non-root user write.
- Because the rootfs is read-only and the base image is `scratch`, the SQLite temp dir
  must not be needed on disk — handled by `temp_store=MEMORY` (§1). Only the PVC mount
  is writable.
- Revisit the memory limit (currently `128Mi`): modernc.org/sqlite's pure-Go VM plus
  `temp_store=MEMORY` raises the floor; bump to e.g. `192Mi`–`256Mi` to avoid an
  OOMKill loop. (Validate empirically during implementation.)

**checkmk-analyzer** — **no deployment manifest exists yet** (`deploy/` contains only
`k8s-analyzer`, `grafana`, `scripts`). Authoring a `deploy/checkmk-analyzer/`
deployment (with the same PVC + securityContext story) is **in scope** for this work,
not a one-line edit. The checkmk binary runs on alpine (not scratch), so `/tmp` exists,
but `temp_store=MEMORY` is still set for consistency.

**Single replica stays mandatory** (RWO + SQLite single-writer). Scaling beyond one
replica requires an external store — explicitly out of scope.

### 9. Metrics

Exposed as methods on the `AlertMetrics` façade (the established pattern — e.g.
`ClaudeTokens` with `kind`/`severity`/`model`, `AlertsDropped` with `reason`), with
nil-safe guards, backed by `PrometheusMetrics` fields registered in `NewPrometheusMetrics`:

- `RecordHistoryEvent(kind string)` → `alert_analyzer_history_events_total{kind="fire"|"analysis"}`.
- `ObserveRecurrence(n int)` → `alert_analyzer_history_recurrence` histogram (Count at injection time).
- `RecordHistoryDrop()` → `alert_analyzer_history_drops_total` (write channel full).
- `RecordHistoryError(op string)` → `alert_analyzer_history_store_errors_total{op="record"|"lookup"|"prune"}`.

All carry the existing `product` ConstLabel applied at registry construction.

### 10. Error handling

`HistoryStore` failures never affect analysis:

- `Lookup` error → log, `RecordHistoryError("lookup")`, return zero `HistoryView`,
  proceed with no injection.
- Write channel full → drop, `RecordHistoryDrop()`, proceed.
- Writer-goroutine INSERT/prune error → log, `RecordHistoryError(...)`, continue draining.
- Construction failure at startup with `HISTORY_ENABLED=true` → fatal. With it false →
  `nopHistoryStore`, never touches disk. Field is never nil (startup nil-checks include it).

### 11. Testing

- **`history_test.go`** — fire/analysis round-trip via the writer goroutine (with a
  synchronous drain hook or `Close()`-then-reopen to avoid timing flakiness); count
  window honored (rows outside TTL excluded); `MAX_ENTRIES` cap; only `kind='analysis'`
  rows in `Prior`; pruning deletes old rows; write-channel-full drops without blocking;
  `nopHistoryStore` returns a zero view and never errors; DB-dir auto-creation.
- **`ParseSummary` tests** — present / absent-with-heading-only-fallback (stores
  nothing) / absent-with-body-fallback / multiple SUMMARY lines (last wins) / trailing
  whitespace / `SUMMARY:` appearing mid-body not matched as the marker line.
- **Pipeline tests** — recurrence section present when `Count > 1`, absent on first
  fire; `HISTORY_INJECT_PRIOR` toggles the `### Prior analyses` sub-block;
  `historySection` produces no double `##` heading; summary is redacted before storage;
  history errors do not fail the pipeline.
- **Handler tests** — `RecordFire` invoked before the cooldown gate (including on the
  suppressed and queue-full branches).

## Phasing

**Phase A — foundation (recurrence awareness)**
HistoryStore interface + `sqliteHistoryStore` (writer goroutine, schema, prune) + nop
impl + `ParseDurationEnv` + `HISTORY_*` config in both mains + PVC for k8s-analyzer +
**new checkmk-analyzer deployment manifest** + `RecordFire` wiring in both handlers +
`Lookup` (count/first/last only) + recurrence-metadata injection + metrics + tests.
`RecordAnalysis` exists in the interface but is **not called yet** — no `kind='analysis'`
rows are written, so `view.Prior` is always empty and no prior block renders regardless
of `HISTORY_INJECT_PRIOR`. Phase A delivers the recurrence block only.

**Phase B — prior-hypothesis injection**
`SUMMARY:` instruction in all **four** system prompts + the forced-summary prompt +
`ParseSummary` + strip-from-ntfy + the `RecordAnalysis` call (storing
`RedactSecrets(summary)`) + the `### Prior analyses` sub-block + anchoring framing. Once
Phase B ships, `HISTORY_INJECT_PRIOR` (default true) gates whether stored summaries are
surfaced in the prompt.

## Out of Scope

- Multi-replica / externally-shared history store (Redis, Postgres). Documented as
  future work; the RWO PVC + single replica is the supported topology.
- A UI or query API over stored history.
- Full-text analysis retention/injection (column reserved, not populated/injected).
- Cross-fingerprint correlation (e.g., "these 5 different alerts are the same incident").
