# Alert History / Cross-Alert Context for Repeated Fingerprints

**Date:** 2026-05-30
**Status:** Approved
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

## Design Decisions (from brainstorming)

These were decided explicitly and are not open for re-litigation during planning:

1. **Staged scope (A then B).** Phase A (recurrence metadata) is the foundation;
   Phase B (prior-hypothesis injection) layers on top behind a separate flag.
2. **Persistence: SQLite on a PVC** (`modernc.org/sqlite`, CGO-free). Not in-memory —
   the headline benefit ("Nth time this week") lives on the hours/days timescale,
   exactly where pod restarts would wipe an in-memory store.
3. **Stored summary = a structured one-line `SUMMARY:`** emitted by Claude itself.
   No separate summarization call (YAGNI), no full-text injection (anchoring + prompt
   cost). A full-text column is kept optional for future audit but is **not** injected.
4. **Count all fires, not just analyses.** A "fire" row is written *before* the
   cooldown gate; a later analysis *updates* that same row with the summary. So
   "Nth time" reflects how often the alert *fired*, not how often it was *analyzed*.
5. **Both analyzers** (k8s + checkmk).

### Resolved judgment calls

- `SetMaxOpenConns(1)` serializes all writes — simplest race-free approach at this
  alert volume, instead of a cooldown-style lock hierarchy.
- Fires dropped due to a full work queue are **not** counted (rare, acceptable).
- The `SUMMARY:` marker line is **stripped from the ntfy notification** (machine
  marker, not user-facing noise).
- A single `HISTORY_TTL` governs both the count window and pruning (no separate
  retention knob). "This week" = set `HISTORY_TTL=168h`.
- Single-replica remains mandatory (RWO PVC + SQLite). Multi-replica would need an
  external store — documented as future work, not built.

## Data Flow

```
Webhook → Auth → enqueue → Worker → ProcessAlert
  │
  ├─ RecordFire(fingerprint, severity) → eventID        # BEFORE cooldown gate
  │
  ├─ Cooldown gate (CheckAndSetWithGroup)
  │     └─ suppressed → return (summary stays NULL; fire still counted)
  │
  ├─ Lookup(fingerprint, HISTORY_TTL, MAX_ENTRIES) → HistoryView
  │     └─ if Count > 1: prepend "Alert Recurrence" section to AnalysisContext
  │            (+ "Prior analyses" sub-block iff HISTORY_INJECT_PRIOR)
  │
  ├─ GatherContext() → AnalysisContext (with injected history section)
  │
  ├─ Analyze() | RunAgenticDiagnostics()  → analysis text (ends with "SUMMARY: …")
  │
  ├─ ParseSummary(analysis) → (summary, body)
  │     └─ RecordAnalysis(eventID, RedactSecrets(summary))   # update the fire row
  │
  └─ PublishAll(body)        # SUMMARY: line stripped from published text
```

The current fire is recorded *before* `Lookup`, so `Count` includes the current
occurrence — "this is the 3rd time" reads naturally. Prior summaries exclude the
current row (its `summary` is still NULL at lookup time).

## Design

### 1. Storage layer (`internal/shared/history.go`)

A single interface with two implementations. The pipeline always calls the interface;
when disabled, a no-op store keeps the hot path branch-free.

```go
type HistoryStore interface {
    // RecordFire inserts a fire event (pre-cooldown). Returns the row id used by
    // RecordAnalysis to attach a summary to the same event.
    RecordFire(ctx context.Context, fingerprint string, sev Severity) (eventID int64, err error)
    // RecordAnalysis attaches the parsed (already redacted) summary to a fire row.
    RecordAnalysis(ctx context.Context, eventID int64, summary string) error
    // Lookup returns recurrence info + the last maxEntries analyzed summaries
    // within the window, newest first.
    Lookup(ctx context.Context, fingerprint string, window time.Duration, maxEntries int) (HistoryView, error)
    Close() error
}

type HistoryView struct {
    Count     int            // fire rows within the window (incl. the current fire)
    FirstSeen time.Time
    LastSeen  time.Time
    Prior     []PriorFinding // analyzed rows with non-NULL summary, newest first
}

type PriorFinding struct {
    At       time.Time
    Summary  string
    Severity Severity
}
```

- `sqliteHistoryStore` — `database/sql` + `modernc.org/sqlite`. Opened with
  `_journal_mode=WAL` and `_busy_timeout=5000`. `db.SetMaxOpenConns(1)` serializes
  writes (5 workers + 1 receipt path; volume is low). Schema created on open via
  `CREATE TABLE IF NOT EXISTS`.
- `nopHistoryStore` — every method is a no-op; `Lookup` returns a zero `HistoryView`.
  Constructed when `HISTORY_ENABLED=false`.

Constructor selects the implementation:
`NewHistoryStore(cfg BaseConfig, product Product) (HistoryStore, error)`.

#### Schema

```sql
CREATE TABLE IF NOT EXISTS alert_events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  fingerprint TEXT    NOT NULL,
  ts          INTEGER NOT NULL,   -- unix seconds
  severity    TEXT    NOT NULL,
  summary     TEXT,               -- NULL until analyzed
  product     TEXT    NOT NULL    -- "k8s" | "checkmk"
);
CREATE INDEX IF NOT EXISTS idx_events_fp_ts ON alert_events(fingerprint, ts);
```

`product` mirrors the metrics ConstLabel so a single shared DB file (if ever co-located)
stays unambiguous; in normal deployment each analyzer has its own DB file.

#### Queries

- `RecordFire`: `INSERT INTO alert_events(fingerprint, ts, severity, summary, product)
  VALUES (?, ?, ?, NULL, ?)`, return `LastInsertId()`. Then opportunistic prune
  (see §6).
- `RecordAnalysis`: `UPDATE alert_events SET summary = ? WHERE id = ?`.
- `Lookup`: one query for `Count`/`FirstSeen`/`LastSeen`
  (`SELECT COUNT(*), MIN(ts), MAX(ts) ... WHERE fingerprint=? AND ts >= ?`) and one for
  prior summaries
  (`SELECT ts, summary, severity ... WHERE fingerprint=? AND ts >= ? AND summary IS NOT NULL
  ORDER BY ts DESC LIMIT ?`).

### 2. Write paths (decision: count fires, not analyses)

In both `internal/k8s/pipeline.go` and `internal/checkmk/pipeline.go`:

- **Fire** — at the top of `ProcessAlert`, *before* the cooldown gate:
  `eventID, _ := deps.History.RecordFire(ctx, alert.Fingerprint, alert.SeverityLevel)`.
  Counts every accepted, dequeued fire. Fires dropped by a full work queue are not
  recorded (they never reach `ProcessAlert`).
- **Summary** — after a successful analysis:
  `deps.History.RecordAnalysis(ctx, eventID, shared.RedactSecrets(summary))`.
  - Cooldown-suppressed → no analysis → `summary` stays NULL (fire counted, no hypothesis).
  - Analysis error → same (NULL). Consistent with existing cooldown-clear-on-failure.

`HistoryStore` is added to each pipeline's `PipelineDeps`. Errors from any history call
are logged + counted, never returned into the pipeline's control flow.

### 3. Read path & prompt injection

After `RecordFire` and a cooldown pass, before/around `GatherContext`:

```go
view, _ := deps.History.Lookup(ctx, alert.Fingerprint, cfg.HistoryTTL, cfg.HistoryMaxEntries)
if view.Count > 1 {
    actx.Sections = append([]ContextSection{historySection(view, cfg.HistoryInjectPrior)}, actx.Sections...)
}
```

`historySection` renders Markdown that slots into the existing `FormatForPrompt()`:

```
## Alert Recurrence
This fingerprint has fired 3 times in the last 6h (first 08:12, last 14:05).

### Prior analyses — treat as hypotheses to verify, not established facts
- 14:05 (warning): OOMKill, likely memory leak in payments-service
- 11:30 (warning): OOMKill after deploy v1.2.3
```

- The recurrence block always renders when `Count > 1`.
- The `### Prior analyses` sub-block renders only when `HistoryInjectPrior` is true
  (Phase B) **and** `view.Prior` is non-empty.
- The "treat as hypotheses to verify, not established facts" framing is the deliberate
  **anchoring mitigation** — keep this wording.
- First occurrence (`Count == 1`) injects nothing (no noise, no extra tokens).

**Prompt-caching note:** the section is injected into the user prompt, not the system
prompt, so it sits outside the system-prompt cache breakpoint. It does not break the
existing breakpoints (system block, tools tail, last `tool_result`); it only shifts the
user-message content, which is already per-request.

### 4. SUMMARY line (Phase B)

System prompts gain a closing instruction (applies to `StaticAnalysisSystemPrompt` and
both agentic tool-loop system prompts, k8s + checkmk):

> End your response with a single line in exactly this form:
> `SUMMARY: <one concise sentence naming the single most likely root cause>`

`ParseSummary(text string) (summary, body string)`:

- Finds the last line matching `^SUMMARY:\s*(.+)$`, trims it, returns it as `summary`
  and returns `body` = the text with that line removed (stripped from the ntfy
  notification).
- Fallback when absent: `summary` = first non-empty line of the body, truncated to
  ~200 chars; `body` unchanged. Ensures Phase B always has *something* to store.

Publish path uses `body`; storage path uses `RedactSecrets(summary)`.

### 5. Redaction

`RecordAnalysis` stores `RedactSecrets(summary)`. The analysis text is not redacted
anywhere today (it is returned from Claude and published as-is); persisting it to disk
is a new exposure surface, closed here at the single storage call.

### 6. Pruning & cardinality

On each `RecordFire`, opportunistically
`DELETE FROM alert_events WHERE ts < (now - HISTORY_TTL)`. This bounds DB size to
roughly `alert_rate × HISTORY_TTL`. No separate retention parameter (YAGNI). No
explicit row cap; revisit only if a real high-cardinality deployment appears.

### 7. Configuration (`BaseConfig`, both analyzers)

| Env var | Default | Meaning |
|---|---|---|
| `HISTORY_ENABLED` | `false` | Master switch. False ⇒ `nopHistoryStore`. |
| `HISTORY_DB_PATH` | `/var/lib/analyzer/history.db` | SQLite file path (on the PVC). |
| `HISTORY_TTL` | `6h` | Lookback window for the recurrence count **and** the prune horizon. |
| `HISTORY_MAX_ENTRIES` | `5` | Max prior hypotheses injected into the prompt. |
| `HISTORY_INJECT_PRIOR` | `true` | Phase-B switch: inject prior summaries. False ⇒ recurrence metadata only (Phase A). |

A/B staging collapses to two flags:
- **Phase A:** `HISTORY_ENABLED=true`, `HISTORY_INJECT_PRIOR=false`.
- **Phase B:** additionally `HISTORY_INJECT_PRIOR=true`.

These are loaded in shared config (`BaseConfig`) since both binaries consume them.

### 8. Deployment

Both `deploy/k8s-analyzer/` and `deploy/checkmk-analyzer/`:

- Add a small `PersistentVolumeClaim` (~100Mi, `ReadWriteOnce`).
- Mount at `/var/lib/analyzer`.
- `securityContext.fsGroup` so the non-root container can write.
- **Single replica stays mandatory** (RWO + SQLite single-writer). Document that
  scaling beyond one replica requires an external store — explicitly out of scope.

### 9. Metrics

Add to the shared metrics façade (carry the existing `product` ConstLabel):

- `alert_analyzer_history_events_total{kind="fire"|"analysis"}` — counter.
- `alert_analyzer_history_recurrence` — histogram of `view.Count` at injection time.
- `alert_analyzer_history_store_errors_total{op="record_fire"|"record_analysis"|"lookup"}`
  — counter.

### 10. Error handling

`HistoryStore` failures never affect analysis:

- `Lookup` error → treat as empty `HistoryView`, proceed with no injection.
- `RecordFire`/`RecordAnalysis` error → log + increment the error counter, proceed.
- Store construction failure at startup with `HISTORY_ENABLED=true` → fatal (operator
  asked for it and it isn't working); with `HISTORY_ENABLED=false` → `nopHistoryStore`,
  never touches disk.

### 11. Testing

- **`history_test.go`** — store round-trip (fire → analysis → lookup); count window
  honored (rows outside TTL excluded); `MAX_ENTRIES` cap; only non-NULL summaries in
  `Prior`; pruning deletes old rows; concurrent writes under `MaxOpenConns(1)`;
  `nopHistoryStore` returns zero view and never errors.
- **`ParseSummary` tests** — present / absent (fallback) / multiple lines (last wins) /
  trailing whitespace / `SUMMARY:` mid-text not matched as the marker line.
- **Pipeline tests** — recurrence section present when `Count > 1`, absent on first
  fire; `HISTORY_INJECT_PRIOR` toggles the `### Prior analyses` sub-block; summary is
  redacted before storage; history errors do not fail the pipeline.

## Phasing

**Phase A — foundation (recurrence awareness)**
HistoryStore + SQLite + nop impl + config + PVC for both deployments + `RecordFire`
wiring + `Lookup` (count/first/last only) + recurrence-metadata injection + metrics +
tests. `RecordAnalysis` exists in the interface but is **not called yet** — `summary`
stays NULL, so `view.Prior` is always empty and no prior block can render regardless of
`HISTORY_INJECT_PRIOR`. Phase A delivers the recurrence block only.

**Phase B — prior-hypothesis injection**
`SUMMARY:` instruction in all three system prompts + `ParseSummary` + strip-from-ntfy +
the `RecordAnalysis` call (storing `RedactSecrets(summary)`) + the `### Prior analyses`
sub-block + anchoring framing. Once Phase B ships, `HISTORY_INJECT_PRIOR` (default true)
gates whether those stored summaries are surfaced in the prompt.

## Out of Scope

- Multi-replica / externally-shared history store (Redis, Postgres). Documented as
  future work; the RWO PVC + single replica is the supported topology.
- A UI or query API over stored history.
- Full-text analysis retention/injection (column reserved, not populated/injected).
- Cross-fingerprint correlation (e.g., "these 5 different alerts are the same incident").
