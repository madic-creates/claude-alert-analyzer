# Alert-Storm Cost & Robustness Protection — Design

**Date**: 2026-05-01
**Status**: Approved (pending implementation plan)
**Updated**: 2026-05-08 — Phase 2 implementation clarifications: failure-phase tracking via `phase` enum + tracker variable in `ProcessAlert` (not separate phase-typed errors); shared `NotifyAggregator` utility (one type, two instances for Storm + Breaker); circuit-breaker wired exclusively in `PipelineDeps` (not in `ClaudeClient`).
**Updated**: 2026-05-08 (post Codex-Review) — Robustness patches: explicit `threshold=0 == disabled` semantics for Storm and Breaker (return `nil` from constructor); circuit-breaker API replaced with Permit-Token pattern (`Acquire`/`Done`) so half-open-probe state is call-local and panic-safe via `defer`; probe-watchdog with max-probe-duration to prevent stuck-state; group-cooldown lifecycle reordered (Group-check before Fingerprint-check + atomic `CheckAndSetWithGroup` with rollback) to prevent orphaned fingerprint entries; group-key fallbacks for empty namespace/service (sentinel suffix); pipeline tracks `analysisErr` separately from named return so post-API err overrides cannot kip the phase decision; NotifyAggregator owner-goroutine pattern with closing-flag and synchronous final flush.
**Updated**: 2026-05-08 (post Codex-Review Round 2) — Three follow-up bugs fixed: NotifyAggregator `Stop()` rewritten as request/reply protocol with `sync.Once`, ack-channel and bounded publish-context (closes Add-after-`closed`-check race, fixes Owner-goroutine-leak on hanging publisher); old `err`-based defer-snippet in 2.3 replaced with explicit reference to phase+analysisErr logic in 2.1 (eliminates contradictory cleanup spec); `CheckAndSetWithGroup` lock-holding-discipline made explicit (both locks held over the entire decision); Aggregator-drop metric `notify_aggregator_drops_total{aggregator}` added so dropped alerts are observable.
**Scope**: Both analyzers (k8s-analyzer, checkmk-analyzer)

## Problem

Beide Analyzer rufen für jeden eingehenden Alert die Claude-API auf, im Worst Case mit einem 10-Runden Tool-Loop (`MAX_AGENT_ROUNDS=10`). Bei einem Alert-Storm — insbesondere mit vielen *unterschiedlichen* Fingerprints (z.B. 50 Pods im selben Deployment crashen) — ergeben sich zwei gekoppelte Risiken:

1. **Hohe API-Kosten**: Der Tool-Loop sendet die ganze Konversationshistorie (inkl. großer Tool-Outputs) bei jeder Runde erneut. Eine einzelne Analyse kann 300 K+ Input-Tokens kosten. Bei 25 in-flight Alerts × 10 Runden × Opus-Pricing entstehen schnell dreistellige Euro-Beträge pro Stunde. Es gibt kein Prompt-Caching, keine Spend-Cap, keine Severity-Differenzierung.

2. **Storm-Verstärker**: Bei voller Worker-Queue (5 Worker + 20 Puffer) wird der Cooldown gecleared und Alertmanager bekommt ein 503. Beim Retry läuft derselbe Alert nochmal in den vollen Workflow. Bei wiederholten 429ern von Anthropic verstärkt das die Last weiter.

Hard kill-switches und persistierter Spend-State sind explizit **out-of-scope** (siehe Brainstorming-Entscheidung). Die Anthropic-Workspace-Spend-Limit dient als externe Backstop. Dieser Design beschreibt ausschließlich Soft-Hebel.

## Goals

- 60–80% Token-Ersparnis bei Storm-Bursts durch Prompt-Caching
- Kostenkontrolle via Severity-Routing: Info-Alerts kosten praktisch nichts, Warning-Alerts ein Bruchteil eines Critical-Alerts
- Storm-Verstärker-Bug (Cooldown-Clear bei API-Fehlern unter Last) eliminieren
- Sichtbarkeit: Operator kann in Grafana Token-Verbrauch und Cache-Hit-Rate je Severity tracken

## Non-Goals

- Hartes Tagesbudget mit Kill-Switch
- Persistierter Cooldown- oder Storm-State (in-memory, Pod-Restart resettet)
- Eigener Spend-Vorwarn-Kanal (Anthropic-Workspace-Limit reicht)
- Dynamische Konfig-Reloads ohne Restart
- **Multi-Replica-Konsistenz**: Cooldown, Storm-Detector und Circuit-Breaker sind alle Pod-lokal in-memory. Bei mehreren Replicas (HPA) werden die Mitigationen fragmentiert — Alertmanager-Retries können auf einem anderen Pod landen und die Mitigation umgehen. Das ist die explizite Wirksamkeitsgrenze des Designs. Operatoren mit Multi-Replica sollten auf Replica-Count=1 + HPA-Scale-up nur bei nachhaltigem Bedarf konfigurieren.

## Architecture

Drei kooperierende, aber separate Komponenten in `internal/shared/`:

1. **`AnalysisPolicy`** — dünne Decision-Schicht. Liest Severity und gibt Modell, Runden-Budget und Group-Cooldown-TTL zurück. Hält einen Read-Pointer auf den `StormDetector`, um `IsDegraded()` zu beantworten. Keine eigenen veränderlichen Felder, keine Concurrency.
2. **`StormDetector`** — Sliding-Window-Counter mit eigenem Lifecycle. Schreibt `Record()` aus dem Webhook-Handler (vor dem Enqueue), liest `Count()` aus `IsDegraded()`.
3. **`CircuitBreaker`** — eigene Komponente. Wird auf **Analyse-Ebene** in der Pipeline gegated (nicht pro HTTP-Call), damit ein Half-Open-Probe genau **eine Analyse** schützt — nicht nur den ersten HTTP-Call eines Tool-Loops. Verwaltet ihren Zustand über das Permit-Token-Pattern `Acquire()/Done(err)` (siehe 2.3) — call-lokal und panic-safe via `defer permit.Done(err)`.

Aufruf-Pattern in den Pipelines (überarbeitet 2026-05-08, post Codex-Review — Permit-Token-Pattern):

```go
// Vor jeder Analyse: Breaker-Gate auf Logical-Call-Ebene.
permit, err := deps.Breaker.Acquire()
if err != nil {
    analysisErr = err  // shared.ErrCircuitOpen — defer schaut auf analysisErr
    return
}
defer permit.Done(analysisErr)  // panic-safe, idempotent (siehe 2.3 Permit-Pattern)

model := deps.Policy.ModelFor(alert.Severity)
rounds := deps.Policy.MaxRoundsFor(alert.Severity)

// Storm-Mode UND Half-Open-Probe forcieren beide rounds=0:
if deps.Policy.IsDegraded() || permit.IsProbe() {
    rounds = 0  // static-only, kein Tool-Loop (siehe 2.2)
}

var analysis string
if rounds == 0 {
    analysis, analysisErr = deps.Claude.Analyze(ctx, model, system, user)
} else {
    analysis, _, _, analysisErr = deps.Claude.RunToolLoop(ctx, model, system, user, tools, rounds, handler)
}
// permit.Done(analysisErr) läuft im defer — Closures sehen den aktuellen Wert von analysisErr.
```

**Zähleinheit**: `permit.Done(err)` wird **pro logischem Analyse-Versuch** gerufen — egal ob die Analyse aus einem einzelnen `Analyze` oder einem 10-Runden `RunToolLoop` bestand. Konsekutive Fehler = konsekutive fehlgeschlagene Analysen, nicht HTTP-Roundtrips. Die internen 2×-Retries (2s/4s) im `ClaudeClient.sendRequest` bleiben unverändert und zählen nicht als separate „Fehler" für den Breaker.

**Half-Open-Semantik**: Das Permit hat ein call-lokales `isProbe`-Flag, das genau für **eine** Analyse `true` ist. Die Mutex-Gate in `Acquire()` markiert die Probe als „aktiv" und gibt das Probe-Permit aus; `Done()` resolved sie. Während die Probe läuft, blockt `Acquire()` aller anderen Goroutinen mit `ErrCircuitOpen`. Der Probe-Watchdog (siehe 2.3) verhindert Stuck-States bei hängender Probe-Goroutine.

### Severity-Modell

Neuer Enum-Typ in `internal/shared/severity.go`:

```go
type Severity int

const (
    SeverityUnknown Severity = iota
    SeverityInfo
    SeverityWarning
    SeverityCritical
)
```

Zwei Normalisierungs-Funktionen — beide bei der Webhook-Verarbeitung im jeweiligen Handler aufgerufen, Ergebnis als neues Feld `Severity shared.Severity` im `AlertPayload` mitgeführt:

- `SeverityFromAlertmanager(labels map[string]string) Severity`
  - `critical`, `page` → `SeverityCritical`
  - `warning`, `notice` → `SeverityWarning`
  - `info` → `SeverityInfo`
  - alles andere oder fehlend → `SeverityWarning` (defensiver Default)

- `SeverityFromCheckMK(serviceState, hostState string) Severity` — der Handler hat heute schon einen Mapping-Switch (`internal/checkmk/handler.go:88-104`). Wir kapseln ihn:
  - `serviceState == "CRITICAL"` → `SeverityCritical`
  - `serviceState == "WARNING"` → `SeverityWarning`
  - `serviceState == "UNKNOWN"` → `SeverityWarning` (defensiver Default)
  - `serviceState == ""` (Host-Level) → fallback auf `hostState`:
    - `"DOWN"`, `"UNREACHABLE"` → `SeverityCritical`
    - sonst → `SeverityWarning`
  - Recovery/OK wird vorher im Handler gefiltert

Das bestehende String-Feld `AlertPayload.Severity` (für ntfy-Anzeige) bleibt unverändert. Der Enum kommt als zusätzliches Feld dazu.

### `shared.AnalysisPolicy`

Dünne Decision-Schicht. Konfig-Werte plus eine Runtime-Delegation an den StormDetector — keine eigenen veränderlichen Felder, keine Mutexe, keine Concurrency-Logik:

```go
type AnalysisPolicy struct {
    DefaultModel     string
    ModelOverrides   map[Severity]string
    DefaultMaxRounds int
    RoundsOverrides  map[Severity]int
    GroupCooldownTTL time.Duration   // 0 == disabled, read-only
    Storm            *StormDetector  // nil if disabled
}

func (p *AnalysisPolicy) ModelFor(sev Severity) string
func (p *AnalysisPolicy) MaxRoundsFor(sev Severity) int
func (p *AnalysisPolicy) IsDegraded() bool  // delegates to Storm.Count() > threshold
```

`ModelFor`/`MaxRoundsFor` fallen auf `DefaultModel`/`DefaultMaxRounds` zurück wenn kein Override gesetzt ist — damit bleibt das Verhalten ohne neue ENV-Variablen identisch zu heute. `IsDegraded()` returned `false` wenn `Storm == nil`.

**Wichtig**: Group-Dedup-Keys leben **nicht** in der Policy, weil sie Source-spezifische Felder lesen (Alertmanager-Labels vs. CheckMK-Notification-Felder). Der jeweilige Handler berechnet den Group-Key direkt und übergibt ihn an `Cooldown.CheckAndSetGroup` (siehe 2.1).

`ClaudeClient.Model` als Konstruktor-Feld entfällt. Stattdessen bekommen `Analyze(ctx, model, system, user)` und `RunToolLoop(ctx, model, system, user, tools, maxRounds, handler)` einen `model string`-Parameter. Aufrufstellen sind ausschließlich in den beiden Pipelines.

**Breaker-Wiring (klargestellt 2026-05-08)**: Der `CircuitBreaker` wird ausschließlich in `PipelineDeps` referenziert. `ClaudeClient` hat **kein** Breaker-Feld. Begründung: Gating muss auf logischer Analyse-Ebene liegen, sonst würde ein Tool-Loop pro HTTP-Roundtrip ein `Acquire()/Done()` triggern und die Half-Open-Probe-Semantik (genau eine Probe = eine Analyse) wäre kaputt.

## Phase 1 — Quick Wins (eigener PR)

Vier Features, niedrigste Verhaltens-Risiken. Alle Defaults so dass das Verhalten ohne neue ENV-Variablen unverändert bleibt — außer dem Caching, das transparent zu Token-Ersparnis führt.

### 1.1 Prompt-Caching (`internal/shared/claude.go`)

`ToolRequest.System` wechselt von `string` zu `[]SystemBlock`:

```go
type SystemBlock struct {
    Type         string        `json:"type"`           // "text"
    Text         string        `json:"text"`
    CacheControl *CacheControl `json:"cache_control,omitempty"`
}
type CacheControl struct {
    Type string `json:"type"` // "ephemeral"
}
```

Cache-Breakpoints werden gesetzt auf **drei Ebenen**:

1. **System-Prompt** — letzter `SystemBlock` bekommt `cache_control: ephemeral`. Statisch je Quelle, hohe Hit-Rate bei Folge-Alerts innerhalb 5 min.
2. **Tool-Definitionen** — letztes Tool im `Tools`-Array bekommt `cache_control: ephemeral`. Anthropic cached alle Tools davor mit. Nur im `RunToolLoop`.
3. **Tool-Loop-Historie** — bei jeder Folge-Runde im `RunToolLoop` bekommt der jeweils letzte `tool_result`-Block in `messages` einen `cache_control: ephemeral`-Marker. Ohne diesen Schritt würden die wachsenden Tool-Outputs bei jeder Runde voll neu fakturiert. Dies ist *der* Hebel im Tool-Loop, nicht (1) und (2). Anthropic erlaubt bis zu 4 Cache-Breakpoints; der älteste fällt automatisch raus.

**Realistische Ersparnis im Tool-Loop**: bei einem 10-Runden-Loop mit großen Tool-Outputs (>50 KB pro Runde) zahlen wir jede Tool-Output-Tranche genau **einmal** als Cache-Creation (~25 % Aufschlag), bei jeder Folge-Runde nur noch ~10 % als Cache-Read. Ohne (3) wäre die Ersparnis dagegen marginal weil System+Tools ein kleiner Anteil am Gesamt-Input ist.

**Mindesttoken-Risiko**: Anthropic cached erst ab Mindestgröße (1024 Tokens für Sonnet/Opus, 2048 für Haiku). Wenn der `system + tools`-Prefix darunter liegt, gibt's null Hit-Rate auf den statischen Teil. Mitigation: in der Implementierung den realen Prefix-Token-Count beim Startup loggen, damit Operator das verifiziert — und nicht künstlich aufpolstern. Wichtig ist Breakpoint (3), der bei großen Tool-Outputs sicher über der Schwelle liegt.

### 1.2 OpenRouter-Auth-Entfernung (Breaking Change, Teil von 1.1)

**Bewusste Breaking Change**, kein Cleanup. `isAnthropicURL` und der `Authorization: Bearer`-Branch in `claude.go` werden entfernt. Header sind danach immer `x-api-key` + `anthropic-version`.

**Rechtfertigung**: Die Codebasis fokussiert sich auf Anthropic als Primärziel. Wer einen Anthropic-API-kompatiblen Provider nutzt, kann via `API_BASE_URL` umlenken — solange dieser Provider `x-api-key`-Auth akzeptiert. Reine OpenRouter-Standard-Endpunkte (mit `Authorization: Bearer`) funktionieren danach nicht mehr.

**Migration**: CLAUDE.md bekommt einen Abschnitt „Breaking Change in v0.X.0 — OpenRouter Bearer-Auth entfernt". Release-Notes erwähnen das prominent. Wenn jemand OpenRouter behalten will, muss der Provider explizit ein `x-api-key`-Auth-Pfad anbieten, oder ein Auth-Proxy davorgesetzt werden.

Diese Änderung ist absichtlich Teil von Phase 1, weil sie den Cache-Code in `claude.go` vereinfacht (eine Code-Pfad statt zwei) und die Spec-Komplexität halbiert. Wer das nicht will, sollte vor Phase-1-Merge einsprechen.

### 1.3 Severity-basiertes Modell-Routing

Neue ENV-Variablen, alle optional:

- `CLAUDE_MODEL_CRITICAL`
- `CLAUDE_MODEL_WARNING`
- `CLAUDE_MODEL_INFO`

Nicht gesetzt → Fallback auf `CLAUDE_MODEL`. `Pipeline` ruft `policy.ModelFor(alert.Severity)` und übergibt das Modell an `Analyze`/`RunToolLoop`. Empfehlung an Operator (in CLAUDE.md): Haiku für Warning/Info, Opus nur für Critical → ~12× Kostenreduktion bei Warnings.

### 1.4 Severity-basierte Agent-Runden

Neue ENV-Variablen, alle optional, Range 0-50:

- `MAX_AGENT_ROUNDS_CRITICAL`
- `MAX_AGENT_ROUNDS_WARNING`
- `MAX_AGENT_ROUNDS_INFO`

Nicht gesetzt → Fallback auf `MAX_AGENT_ROUNDS`. **Special case `0`**: kein Tool-Loop, nur statische Analyse via `Analyze`. Pipeline-Switch:

```go
if rounds == 0 {
    analysis, err = deps.Claude.Analyze(ctx, model, system, user)
} else {
    analysis, _, _, err = deps.Claude.RunToolLoop(ctx, model, system, user, tools, rounds, handler)
}
```

`MAX_AGENT_ROUNDS_INFO=0` ist der größte Spar-Hebel für rauschende Info-Alerts.

### 1.5 Kosten-Sichtbarkeit (`internal/shared/prom_metrics.go`)

Neue Counter, alle mit Labels `{source, severity, model}`:

- `claude_input_tokens_total`
- `claude_output_tokens_total`
- `claude_cache_creation_tokens_total` — neu erstellte Cache-Einträge (~25 % teurer als regulärer Input)
- `claude_cache_read_tokens_total` — Cache-Hits (~10 % von regulärem Input)

`Usage`-Struct in `claude.go` wird um `CacheCreationInputTokens` und `CacheReadInputTokens` erweitert. Befüllt nach jedem API-Response. Cache-Hit-Rate ist als abgeleitete Grafana-Query verfügbar:

```
sum(rate(claude_cache_read_tokens_total[5m]))
  / sum(rate(claude_cache_read_tokens_total[5m]) + rate(claude_cache_creation_tokens_total[5m]) + rate(claude_input_tokens_total[5m]))
```

## Phase 2 — Storm Robustness (eigener PR)

Drei Features. Alle per Default deaktiviert (`THRESHOLD=0` / `SECONDS=0`), opt-in via ENV.

### 2.1 Group-Cooldown

`CooldownManager` bekommt drei neue Methoden mit eigener Map und eigenem Mutex-Pfad. **Wichtig (klargestellt 2026-05-08, post Codex-Review)**: weil das naive Pattern „erst Fingerprint setzen, dann Group prüfen" einen Lifecycle-Bug erzeugt (Fingerprint wird gesetzt, obwohl Group dedupliziert und keine Analyse stattfindet → defer behält dann irrtümlich Cooldowns), gibt es eine atomare kombinierte Methode mit Rollback:

```go
// Einzelmethoden bleiben für Test- und Edge-Cases erhalten:
func (cm *CooldownManager) CheckAndSetGroup(groupKey string, ttl time.Duration) bool
func (cm *CooldownManager) ClearGroup(groupKey string)  // für Failure-Cleanup

// Kombinierte Methode — der Default-Pfad im Handler:
//
// Reihenfolge: Group zuerst checken (wenn enabled), dann Fingerprint.
// Wenn Fingerprint blockt nachdem Group gesetzt wurde → Group rollbacken.
//
// **Lock-Discipline (klargestellt post Codex-Review Round 2)**: BEIDE Mutexe
// werden über die GESAMTE Entscheidung gehalten — nicht hintereinander
// einzeln genommen und freigegeben. Reihenfolge: groupMu.Lock() zuerst,
// dann fpMu.Lock(); Unlock in umgekehrter Reihenfolge via defer. Keine
// andere Methode im Cooldown-Manager hält die Locks in umgekehrter
// Reihenfolge (Lock-Hierarchy ist groupMu < fpMu), daher kein Deadlock.
// Ohne dieses Pattern wäre die behauptete Atomik nur scheinbar — ein
// paralleler Caller könnte zwischen den Locks reinschlüpfen und Group
// für denselben Key setzen während wir gerade Rollback machen.
//
// Returns true und setzt beide, wenn weder Group noch Fingerprint im Cooldown sind.
// Returns false und setzt KEINE der beiden, wenn eine der beiden blockt.
//
// groupKey == "" oder groupTTL == 0 → Group wird übersprungen, nur Fingerprint.
func (cm *CooldownManager) CheckAndSetWithGroup(
    fingerprint string, fpTTL time.Duration,
    groupKey string, groupTTL time.Duration,
) bool
```

**Key-Berechnung im Handler** (Source-spezifisch, nicht in `shared`):

- `internal/k8s/handler.go`: `groupKey = labels["alertname"] + ":" + labels["namespace"]`
  - **Fallback bei leerem `namespace`** (clusterweite Alerts wie z.B. `KubeAPIDown`): `groupKey = labels["alertname"] + ":_cluster_"` — Sentinel-Suffix, damit zwei verschiedene Cluster-weite Alerts nicht kollidieren und ein leerer Namespace nicht in einem leeren Suffix endet (was wiederum zu falschen Kollisionen mit anderen Alerts ohne Namespace führen könnte).
- `internal/checkmk/handler.go`: `groupKey = notif.Hostname + ":" + notif.ServiceDescription`
  - **Fallback bei leerem `ServiceDescription`** (Host-Level-Events wie `DOWN`/`UNREACHABLE`): `groupKey = notif.Hostname + ":_host_"` — analog, expliziter Marker, keine impliziten leeren Strings.

**Group-Key bleibt im Storm-Mode unverändert** — Gröberer Key wäre zu aggressiv (z.B. „CPU load" auf 50 verschiedenen Hosts → alle deduped zu einem Alert). Der Storm-Mode-Hebel ist `rounds=0`, nicht aggressivere Dedup. Wenn ein Operator gröbere Cluster-weite Dedup will, ist das eine Konfig-Entscheidung in `GROUP_COOLDOWN_SECONDS`, nicht ein automatischer Storm-Effekt.

**Lifecycle** (klargestellt 2026-05-08, post Codex-Review) — analog zum Fingerprint-Cooldown, mit Differenzierung nach Failure-Phase. Der Handler ruft die kombinierte atomare Methode:

```
1. CheckAndSetWithGroup(fp, fpTTL, group, groupTTL) → wenn false, fertig (no enqueue)
   → garantiert: entweder beide Cooldowns gesetzt oder keiner
2. Enqueue:
   - Erfolg: Cooldowns bleiben gesetzt
   - Failure (queue voll): ClearGroup(groupKey) UND Cooldown.Clear(fingerprint)
                            → Alertmanager-Retry kann durchkommen
3. Pipeline-Failure (defer): differenziert nach Phase, in der der Fehler entstand:
   - Pre-API (Context-Gather, Validierung): ClearGroup + Cooldown.Clear
                                              → Retry ist billig, Analyse hat noch nicht stattgefunden
   - API-Phase (Claude-Aufruf, !ErrCircuitOpen): ClearGroup + Cooldown.Clear
                                                  → API-Fehler, Retry kann sinnvoll sein
   - API-Phase mit ErrCircuitOpen: NICHT clearen
                                    → Verstärker-Mitigation (siehe 2.3)
   - Post-API (Notification-Publish, ntfy): NICHT clearen
                                              → Analyse war erfolgreich, kein Re-Analyse-Trigger;
                                                ntfy-Failure ist separat (loggen, Metrik), aber
                                                eine teure Re-Analyse macht keinen Sinn
```

**Implementierung (klargestellt 2026-05-08, robustness 2026-05-08)**: `ProcessAlert` führt eine lokale `phase` Variable vom Typ `failurePhase` (Enum: `phasePreAPI` | `phaseAPI` | `phasePostAPI`). Initialwert ist `phasePreAPI`. Nach erfolgreichem `gatherContext` und vor dem Breaker-Gate wechselt sie auf `phaseAPI`. Nach `permit.Done(nil)` (Analyse erfolgreich, siehe 2.3 Permit-Pattern) wechselt sie auf `phasePostAPI`.

**Wichtig (post Codex-Review)**: Der `defer` liest **nicht** den named return `err`, sondern eine separate lokale `analysisErr` Variable, die nur in der API-Phase gesetzt wird. So kann ein späterer Post-API-Fehler (z.B. ntfy-publish) den named return `err` überschreiben, ohne die Phase-Entscheidung des `defer` zu kippen.

```go
var (
    phase       failurePhase = phasePreAPI
    analysisErr error
    groupKey    string  // gesetzt im Handler-Pfad, im Pipeline-Pfad als Argument
)
defer func() {
    switch phase {
    case phasePreAPI:
        // Pre-API-Failure (gather/validation): cleart immer
        deps.Cooldown.Clear(alert.Fingerprint)
        if groupKey != "" { deps.Cooldown.ClearGroup(groupKey) }
    case phaseAPI:
        // API-Phase: cleart nur wenn analysisErr != nil und nicht ErrCircuitOpen
        if analysisErr == nil { return }
        if errors.Is(analysisErr, shared.ErrCircuitOpen) { return }  // Verstärker-Mitigation
        deps.Cooldown.Clear(alert.Fingerprint)
        if groupKey != "" { deps.Cooldown.ClearGroup(groupKey) }
    case phasePostAPI:
        // Analyse war erfolgreich, ntfy-Failure separat geloggt
        return
    }
}()

// ... gather context, set phase = phaseAPI ...

permit, err := deps.Breaker.Acquire()
if err != nil {
    analysisErr = err  // ErrCircuitOpen oder breaker-disabled-no-op-permit-Fehler
    return
}
defer permit.Done(analysisErr)  // panic-safe cleanup, siehe 2.3

// ... model, rounds bestimmen, Analyze oder RunToolLoop aufrufen ...
analysisErr = err  // kopieren, NICHT named return überschreiben

if analysisErr != nil {
    // notification-publish kann den named return err setzen; phase bleibt phaseAPI,
    // analysisErr bleibt der Analyse-Fehler — defer entscheidet korrekt.
    publishFailureNotification(...)
    return
}

phase = phasePostAPI
// ... publishAll für Erfolgs-Notification; falls error, named return err wird gesetzt,
//     aber phase=phasePostAPI signalisiert "keep cooldowns".
```

**Panic-Pfad**: Der bestehende Panic-Recover-defer (`recover() != nil`) muss seine pauschale `Cooldown.Clear()`-Logik **entfernen** und stattdessen analog zur Phase-Logik handeln. Empfehlung: Panic-Recover setzt `analysisErr = errors.New("panic recovered: ...")` und delegiert das Cooldown-Cleanup an den Phase-defer. So bleiben Verstärker-Mitigation und Panic-Mitigation konsistent.

Tests setzen `phase` über Mock-Schritte, die kontrolliert in jedem Stadium fehlschlagen, und prüfen `analysisErr` separat von `err`.

Empfohlener Wert: `GROUP_COOLDOWN_SECONDS=60`. Kurz genug dass legitime Folge-Alerts nach einer Minute durchkommen, lang genug um Storms zu absorbieren.

### 2.2 Storm-Mode

`StormDetector` in `shared`: Sliding-Window-Counter, 5-min-Fenster, 1-min-Buckets.

```go
type StormDetector struct {
    threshold int
    now       func() time.Time  // injectable for tests
    mu        sync.Mutex
    buckets   [5]bucket         // 1-min granularity
}
type bucket struct {
    minute int64  // Unix minute, -1 = empty
    count  int
}
func (d *StormDetector) Record()
func (d *StormDetector) Count() int
```

**`THRESHOLD=0 == disabled` (klargestellt 2026-05-08, post Codex-Review)**: Naive Implementierung `Count() > threshold` würde bei `threshold=0` ab dem ersten Alert degradieren — der Default wäre dann „immer degraded" statt „aus". Konkrete Lösung:

- Konstruktor: `NewStormDetector(threshold int, now func() time.Time) *StormDetector` — wenn `threshold <= 0`, returnt `nil`.
- `AnalysisPolicy.Storm` Pointer ist nil-fähig. `policy.IsDegraded()` returnt `false` wenn `Storm == nil`.
- Handler ruft `detector.Record()` defensiv hinter einem `if detector != nil`-Check, sonst kein No-Op.
- Damit ist „disabled" der Default, ohne Sentinel-Werte oder magic-Constants im Hot-Path.

**Concurrency-Entscheidung**: `sync.Mutex`, keine Atomics. Bucket-Rotation plus konsistenter Count-Aggregation ist mit reinen Atomics fehleranfällig (race zwischen Bucket-Wechsel und Read). Mutex ist hier billig — `Record()` läuft einmal pro eingehendem Webhook-Alert (selbst bei einem Burst maximal niedrige Hunderte pro Minute pro Analyzer).

**Wo `Record()` aufgerufen wird**: im Webhook-Handler **vor** dem Enqueue, **nach** dem Cooldown-Check. Damit zählen wir Eingangsdruck (echte neue Alerts), nicht erfolgreiche Aufnahmen — Storm-Mode greift auch dann, wenn die Queue bereits überläuft und Alerts mit 503 abgewiesen werden. Cooldown-deduplizierte Alerts zählen *nicht*, weil das System sie schon absorbiert hat.

`policy.IsDegraded()` returned `true` wenn `Storm != nil && detector.Count() > threshold`.

**Verhalten im Degraded-Mode**:
- Pipeline setzt `rounds = 0` wenn `policy.IsDegraded()` — nur statische `Analyze`-Calls, kein Tool-Loop. Das ist der härteste Kosten- und Last-Hebel: kein Tool-Use, keine wachsende Konversationshistorie, ein einzelner Round-Trip pro Alert.
- Group-Cooldown-Key bleibt unverändert (siehe 2.1) — nicht aggressiver, um operative Risiken durch Übermäßige Cluster-Dedup zu vermeiden
- ntfy-Aggregator: pro `STORM_MODE_NOTIFY_INTERVAL` eine Sammelmeldung mit Counter und Beispiel-Alerts statt N Einzelnachrichten — implementiert als Instance des shared `NotifyAggregator` (siehe 2.4)

Neuer Gauge `storm_mode_active{source}` (0/1) für Operator-Alerting.

ENV: `STORM_MODE_THRESHOLD=0` (Default = aus, suggested: 50), `STORM_MODE_NOTIFY_INTERVAL=60s`.

### 2.3 Anthropic Circuit-Breaker

**API überarbeitet 2026-05-08 (post Codex-Review)** — der ursprüngliche Vorschlag mit `BeforeCall()` + `IsHalfOpenProbe()` + `RecordResult()` hatte zwei Strukturprobleme:

1. **Probe-Korrelation war global, nicht call-lokal**: `IsHalfOpenProbe()` gab den Probe-Status aus globalem State zurück, nicht gebunden an den konkreten Caller, der `BeforeCall()` gemacht hat.
2. **Panic-Lücke**: Wenn zwischen `BeforeCall()=nil` und `RecordResult()` ein Panic oder ein vergessener Pfad-Return passierte, blieb `halfOpenInFlight=true` für immer.

Die neue API verwendet ein **Permit-Token-Pattern**, das beide Probleme strukturell löst:

```go
var ErrCircuitOpen = errors.New("circuit breaker open")

type CircuitBreaker struct {
    threshold        int
    openDuration     time.Duration
    maxProbeDuration time.Duration   // Watchdog: stuck probe nach diesem Timeout zwangsfreigeben
    now              func() time.Time

    mu               sync.Mutex
    state            breakerState   // closed | open | halfOpen
    consecFailures   int
    openedAt         time.Time
    probeStartedAt   time.Time      // gesetzt mit halfOpenInFlight; für Watchdog
    halfOpenInFlight bool           // Mutex-Gate für die eine Probe-Analyse
}

// Permit ist ein Call-Token, das genau einen logischen Analyse-Versuch repräsentiert.
// Die Pipeline ruft Acquire(), defer'd permit.Done(analysisErr) und nutzt permit.IsProbe()
// um rounds=0 zu erzwingen wenn nötig. Done() ist idempotent — mehrfache Aufrufe haben
// keinen Effekt nach dem ersten.
type Permit struct {
    breaker *CircuitBreaker
    isProbe bool
    used    bool          // intern, durch breaker.mu geschützt; idempotency
}

// Acquire prüft den Breaker-Zustand und gibt entweder ein Permit zurück oder
// ErrCircuitOpen. Ein nil-Receiver (disabled breaker) gibt immer ein no-op-Permit
// zurück (used=true sofort), kein Fehler. Damit ist der Pipeline-Pfad uniform.
func (b *CircuitBreaker) Acquire() (*Permit, error)

// IsProbe returnt true, wenn dieses Permit genau die eine erlaubte Half-Open-Probe ist.
// Die Pipeline nutzt das, um rounds=0 zu erzwingen (Probe = static-only Analyse).
func (p *Permit) IsProbe() bool

// Done resolved das Permit. Idempotent: nur der erste Aufruf wirkt.
// err == nil → state-machine: probe success → closed, consecFailures = 0.
// err != nil → state-machine: failure incrementiert consecFailures (closed),
//                              oder probe failure → open, openedAt = now().
// Defer-friendly: `defer permit.Done(analysisErr)` cleant auch bei panic auf
// (panic → defers laufen → halfOpenInFlight wird freigegeben).
func (p *Permit) Done(err error)
```

**Drei Zustände** (state-machine unverändert, nur API anders):

- **Closed** (normal): `Acquire()` returnt Permit mit `isProbe=false`. `Done(nil)` resetet `consecFailures = 0`. `Done(err)` mit `err != nil` inkrementiert; bei `threshold` → Wechsel zu **open**, `openedAt = now()`.
- **Open**: `Acquire()` returnt `nil, ErrCircuitOpen` solange `now() - openedAt < openDuration`. Danach Wechsel zu **half-open** beim nächsten `Acquire()`.
- **Half-Open**: erlaubt **genau eine** Probe-Analyse. `Acquire()` setzt unter Mutex `halfOpenInFlight = true`, `probeStartedAt = now()`, returnt Permit mit `isProbe=true` für genau diesen einen Caller. Alle parallelen `Acquire()`-Aufrufe in dem Zeitfenster bekommen `nil, ErrCircuitOpen`. `permit.Done(nil)` → closed, `halfOpenInFlight=false`. `permit.Done(err)` → open, `openedAt = now()`, `halfOpenInFlight=false`.

**Probe-Watchdog (post Codex-Review)**: Falls eine Probe-Goroutine hängt (z.B. Tool-Loop blockiert), würde `halfOpenInFlight=true` ohne Watchdog beliebig lange den Breaker blockieren. Mitigation: bei jedem `Acquire()` im Half-Open-Zustand wird zuerst `probeStartedAt + maxProbeDuration < now()` geprüft — wenn ja, behandelt der Breaker die hängende Probe als gescheitert (`halfOpenInFlight=false`, state=open, openedAt=now()), und der aktuelle Caller bekommt `ErrCircuitOpen` (nicht ein neues Probe-Permit, weil der Breaker nun im open-Zustand ist und erst nach `openDuration` wieder half-open wird). `maxProbeDuration` Default `60s` plus `CIRCUIT_BREAKER_MAX_PROBE_SECONDS` als optionale ENV.

**Idempotenz von `Done`**: Wenn defer mehrfach aufgerufen wird (z.B. weil Code redundant cleared), werden alle Aufrufe nach dem ersten ignoriert. Das schützt vor unbeabsichtigter Doppel-Counting beim consecFailures-Increment.

**Wichtig: Gate-Ebene = Logical-Call**. `Acquire()/Done()` werden in der Pipeline aufgerufen, **um den ganzen Tool-Loop herum**, nicht in `ClaudeClient.sendRequest`. Begründung: ein Tool-Loop ist EIN logischer API-Call; ein Half-Open-Probe soll genau eine *Analyse* zulassen, nicht den ersten HTTP-Call und dann unbegrenzt weitere innerhalb derselben Analyse durchwinken.

**Zähleinheit**: `Done(err != nil)` wird **pro logischer Analyse** gerufen — egal ob `Analyze` (1 HTTP) oder `RunToolLoop` (bis zu 11 HTTP intern). Konsekutive Fehler = konsekutive fehlgeschlagene Analysen.

**`THRESHOLD=0 == disabled`**: Konstruktor `NewCircuitBreaker(threshold int, openDuration, maxProbeDuration time.Duration, now func() time.Time) *CircuitBreaker` returnt `nil` wenn `threshold <= 0`. Acquire() auf nil-Receiver gibt ein no-op-Permit zurück (sofortiges Done(_) ist OK, IsProbe() returnt false). Damit ist Pipeline-Code uniform unabhängig von Konfiguration.

**Wiring in der Pipeline** (siehe auch 2.1 Phase-Tracking):

```go
permit, err := deps.Breaker.Acquire()
if err != nil { /* analysisErr = err; return */ }
defer permit.Done(analysisErr)  // panic-safe, idempotent

// Storm UND Half-Open-Probe forcieren beide rounds=0:
if deps.Policy.IsDegraded() || permit.IsProbe() {
    rounds = 0
}
```

**Wichtige Verstärker-Mitigation**: Der Cooldown-Cleanup-`defer` in `pipeline.go` darf bei `ErrCircuitOpen` die Cooldowns **nicht** clearen — sonst hämmert Alertmanager bei offenem Breaker weiter. Diese Logik ist Teil der phase-differenzierten Cleanup-Logik aus 2.1 und wird dort konkret implementiert. Kurz: in `phaseAPI` wird bei `errors.Is(analysisErr, ErrCircuitOpen)` ein `return` aus dem switch gemacht; Fingerprint- und Group-Cooldown bleiben aktiv und absorbieren die Last. Siehe Code-Template in Section 2.1 unter „Implementierung (klargestellt 2026-05-08, robustness 2026-05-08)".

ntfy-Aggregator: pro `CIRCUIT_BREAKER_NOTIFY_INTERVAL` eine Sammel-Notiz „API rate-limited, n alerts pending manual review" — implementiert als zweite Instance des shared `NotifyAggregator` (siehe 2.4).

Neuer Gauge `claude_circuit_breaker_state{source}` (0=closed, 1=open, 2=half-open). Encoding-Reihenfolge entspricht der Implementierung; eine frühere Spec-Iteration vertauschte 1 und 2 — Implementierung + Operator-Doku sind die Source of Truth.

ENV: `CIRCUIT_BREAKER_THRESHOLD=0` (Default = aus, suggested: 5), `CIRCUIT_BREAKER_OPEN_SECONDS=60`, `CIRCUIT_BREAKER_NOTIFY_INTERVAL=300s`.

### 2.4 Shared NotifyAggregator (klargestellt 2026-05-08, robustness 2026-05-08, request-reply 2026-05-08)

Storm-Mode und Circuit-Breaker brauchen beide dieselbe Mechanik: Alerts während eines Intervalls puffern und am Intervallende eine zusammengefasste ntfy-Nachricht emittieren. Statt zwei Implementierungen kommt **eine** generische Komponente in `internal/shared/notify_aggregator.go`.

**Concurrency-Pattern**: Single-Owner-Goroutine. Ein dedizierter Goroutine besitzt Buffer + Timer; `Add()` und `Stop()` kommunizieren ausschließlich über Channels mit dem Owner. Das eliminiert die ursprünglichen mutex+timer-Races vollständig.

**Stop-Protokoll (post Codex-Review Round 2)**: Der initial skizzierte „closed-Flag + drain"-Ansatz hatte zwei Bugs: (a) Add-Race zwischen Flag-Check und Drain → Items konnten verloren gehen; (b) `flush()` mit `context.Background()` → bei hängendem Publisher blockiert die Owner-Goroutine permanent und leakt. Die Lösung ist **`Stop()` als Request/Reply-Protokoll** mit ack-Channel und bounded publish-context:

```go
type NotifyAggregator struct {
    publishers []Publisher
    interval   time.Duration
    titleFmt   string             // z.B. "Storm-mode active: %d alerts"
    priority   string             // z.B. "4" für Storm, "5" für Breaker
    dropMetric *Counter           // Prometheus counter für gedropte Alerts (siehe unten)

    in        chan string         // Add() → Owner; gepuffert (z.B. 100)
    stopReq   chan stopRequest    // Stop() → Owner mit ack-Channel
    stopOnce  sync.Once           // Stop() ist idempotent
    stopped   chan struct{}       // geschlossen wenn Owner-Goroutine beendet
}

type stopRequest struct {
    ctx context.Context  // Owner nutzt diesen ctx für den Final-Flush-PublishAll
    ack chan error       // Owner signalisiert Abschluss + ggf. ctx.Err()
}

func NewNotifyAggregator(pubs []Publisher, interval time.Duration, titleFmt, priority string, dropMetric *Counter) *NotifyAggregator
// Konstruktor spawnt automatisch die Owner-Goroutine. nil-publishers oder interval==0 → returnt nil.

// Add: non-blocking. Returnt false wenn Aggregator bereits gestoppt ODER der in-channel voll ist.
// In beiden Fällen wird dropMetric.Inc() gerufen — dropped Alerts sind beobachtbar.
func (a *NotifyAggregator) Add(alertTitle string) bool

// Stop: idempotent via sync.Once. Erster Aufruf sendet stopRequest{ctx, ack} an Owner und wartet
// auf ack. Folge-Aufrufe warten lediglich auf <-a.stopped.
//
// Returnt nil bei sauberem Abschluss, ctx.Err() bei Timeout.
//
// Ablauf im Owner: nach Empfang der stopRequest setzt er state=stopping, drain't den in-channel
// bis er leer ist, ruft flush(req.ctx) (bounded — kein context.Background() mehr), schickt
// flush-Result an req.ack, schließt a.stopped, beendet sich.
func (a *NotifyAggregator) Stop(ctx context.Context) error
```

**Add-Logik (race-frei via select)**:

```go
func (a *NotifyAggregator) Add(alertTitle string) bool {
    select {
    case <-a.stopped:
        a.dropMetric.Inc()
        return false  // bereits gestoppt
    default:
    }
    select {
    case a.in <- alertTitle:
        return true
    case <-a.stopped:
        a.dropMetric.Inc()
        return false  // gestoppt zwischen den beiden Selects
    default:
        a.dropMetric.Inc()
        return false  // channel voll (Backpressure)
    }
}
```

Der zweite `select` ist kritisch: er behandelt den Fall, dass `Stop()` zwischen den beiden Selects feuert UND der channel voll ist — das ursprüngliche Pattern hätte hier blockierend in den Channel geschrieben und am Drain teilgenommen. Durch das `default` ist der Channel-Send non-blocking; durch das parallele `<-a.stopped` wird der Stopp-Pfad bevorzugt erkannt.

**Owner-Goroutine-Logik**:

```go
func (a *NotifyAggregator) run() {
    defer close(a.stopped)
    var buffer []string
    var timer *time.Timer

    flush := func(ctx context.Context) error {
        if len(buffer) == 0 { return nil }
        title := fmt.Sprintf(a.titleFmt, len(buffer))
        body := strings.Join(buffer, "\n")
        err := PublishAll(ctx, a.publishers, title, a.priority, body)
        buffer = nil  // immer leeren, auch bei publish-Error (Drop-Logging)
        return err
    }

    for {
        var timerC <-chan time.Time
        if timer != nil { timerC = timer.C }

        select {
        case alertTitle := <-a.in:
            buffer = append(buffer, alertTitle)
            if timer == nil {
                timer = time.NewTimer(a.interval)
            }
        case <-timerC:
            timer = nil
            // Tick-Flush ist mit context.Background — kein bounded ctx, weil im
            // Steady-State der Publish-Timeout (NtfyPublisher) selbst greift.
            _ = flush(context.Background())
        case req := <-a.stopReq:
            if timer != nil { timer.Stop() }
            // Drain pending in-channel non-blocking
            for {
                select {
                case alertTitle := <-a.in:
                    buffer = append(buffer, alertTitle)
                default:
                    goto done
                }
            }
        done:
            // Final-Flush mit dem vom Caller gegebenen ctx — KEIN context.Background mehr.
            // Wenn Publisher hängt und ctx läuft ab, wird der publish-Call abgebrochen
            // und wir leaken nicht.
            req.ack <- flush(req.ctx)
            return
        }
    }
}
```

**Lifecycle-Garantien**:

- **Kein Race zwischen Tick und Stop**: nur die Owner-Goroutine schreibt am Buffer. `Stop()` signalisiert über `stopReq`-Channel, Owner sieht den Tick-vs-Stop-Race im `select` deterministisch.
- **Kein Add-after-Stop-Race**: `Add()` benutzt `<-a.stopped` als Signal in beiden Selects; sobald die Owner-Goroutine `close(a.stopped)` ausgeführt hat (am Funktionsende, NACH dem Drain+Flush), kann kein `Add()` mehr durchkommen. Add-Versuche, die genau in diesem Race-Fenster lagen, werden als Drop gezählt — sichtbar in der Metrik.
- **Owner-Goroutine leakt nicht**: Final-Flush nutzt den vom Stop-Caller übergebenen `ctx`. Wenn Publisher hängt und `ctx` abläuft, gibt `PublishAll` `ctx.Err()` zurück, der Owner schreibt das in `req.ack` und beendet sich. Stop-Caller bekommt `ctx.Err()`.
- **Idempotenz von Stop**: `sync.Once` garantiert, dass nur der erste `Stop()`-Aufruf `stopRequest` schickt. Folgeaufrufe warten via `<-a.stopped` und bekommen denselben `nil` (sauberer Shutdown war's beim Erstaufruf) oder `ctx.Err()` zurück; die Implementierung speichert das Ergebnis des ersten Aufrufs in einem privaten Feld unter dem `sync.Once`.
- **Drop-Beobachtbarkeit**: jeder `Add()`-Drop (gestoppt, channel voll, race gegen Stop) inkrementiert `notify_aggregator_drops_total{aggregator="storm"|"breaker"}`. Operator sieht in Grafana, ob der Aggregator unter Last Items wegwirft.

**Drop-Metrik (klargestellt post Codex-Review Round 2)**:

```
notify_aggregator_drops_total{aggregator}  # Prometheus counter
  # aggregator = "storm" | "breaker"
```

Erhöht bei: in-channel voll (Backpressure), Add-nach-Stop, Race zwischen Add und Stop. **Wichtig**: die Sammelmeldungen, die der Aggregator publisht, repräsentieren NICHT den vollen Eingangsstrom — sie sind eine untere Schranke. Die Differenz ist diese Metrik. Operatoren sollten sie in der Storm-/Breaker-Severity berücksichtigen.

**Wiring**:
- Storm-Instance: `interval = STORM_MODE_NOTIFY_INTERVAL`, Title `"Storm-mode active: %d alerts in last interval"`, Priority `"4"`, `dropMetric.WithLabelValues("storm")`.
- Breaker-Instance: `interval = CIRCUIT_BREAKER_NOTIFY_INTERVAL`, Title `"API rate-limited: %d alerts pending manual review"`, Priority `"5"`, `dropMetric.WithLabelValues("breaker")`.
- Beide Instanzen werden in `cmd/*-analyzer/main.go` konstruiert und in `PipelineDeps` gehängt; Pipelines rufen `StormNotify.Add(...)` bzw. `BreakerNotify.Add(...)` statt direkt `PublishAll`, wenn der entsprechende Modus aktiv ist.
- Beide Aggregator-`Stop()`-Calls hängen am SIGTERM-Pfad in `server.go` zwischen Worker-Drain und `shutdown complete`. Stop-Aufrufe bekommen einen `ctx` mit Timeout (z.B. 10s aus dem Shutdown-Budget).

**Test-Strategie**: `notify_aggregator_test.go` mit kurzen Realtime-Intervals (z.B. 50 ms), `-race` Pflicht:
- Concurrency: 100 parallele `Add()` + ein Flush-Tick → genau eine `PublishAll` mit allen 100 Items im Body
- Stop-Drain: 50 `Add()` direkt vor `Stop(ctx)` → alle 50 landen im finalen Flush; `Stop` returnt nil
- Add-after-Stop: `Stop()` abgeschlossen → 100 `Add()`s returnen false, dropMetric == 100, kein Panic
- Stop-Race: 1000 `Add()`-Goroutinen + paralleles `Stop()` → sum(published) + sum(drops) == 1000 (kein verlorener Alert)
- **Hung-Publisher-Test**: Publisher blockiert künstlich → `Stop(ctx)` mit ctx-Timeout 100 ms → returnt ctx.DeadlineExceeded innerhalb 110 ms; `<-a.stopped` schließt; keine Goroutine bleibt nach 200 ms aktiv (verifiziert via `runtime.NumGoroutine` Δ-Check oder `goleak`)
- Stop-Idempotency: drei parallele `Stop(ctx)`-Aufrufe → genau ein stopRequest gesendet (verifiziert via Mock-Owner-Counter), alle drei bekommen denselben Rückgabewert

### 2.5 Storm-Mode + Circuit-Breaker — Interaktions-Matrix

| Storm aktiv | Breaker-Zustand | Verhalten | Notification |
|---|---|---|---|
| ja | closed | `Analyze`-only (`rounds=0`) — Storm-degraded | Storm-Aggregat |
| ja | open | kein API-Call, `ErrCircuitOpen`, Cooldowns bleiben | Breaker-Aggregat (höhere Priorität) |
| ja | half-open | Probe-Analyse mit `rounds=0` (Storm + Half-Open beide forcieren), alle anderen `ErrCircuitOpen` | Breaker-Aggregat |
| nein | closed | normaler API-Call mit konfigurierten Runden | normale ntfy |
| nein | open | kein API-Call, Cooldowns bleiben | Breaker-Aggregat |
| nein | half-open | Probe-Analyse mit `rounds=0` (Half-Open zwingt `rounds=0`), alle anderen `ErrCircuitOpen` | Breaker-Aggregat |

**Kurzregel**: Breaker-Zustand dominiert die Aufrufberechtigung. Pipeline-Logic für Runden-Bestimmung:

```go
if policy.IsDegraded() || permit.IsProbe() {
    rounds = 0  // beide Modi forcieren static-only
}
```

Damit ist die teuerste Variante einer Probe-Analyse begrenzt auf einen `Analyze`-Call mit dem konfigurierten Modell, niemals ein voller Tool-Loop. Notification-Priorität: Breaker-Aggregat > Storm-Aggregat (operativ wichtiger). Beide Gauges sind gleichzeitig aktiv und sichtbar in Grafana.

## Configuration Reference

```
# Phase 1 — Severity-basiertes Routing (alle optional, fallback = CLAUDE_MODEL / MAX_AGENT_ROUNDS)
CLAUDE_MODEL_CRITICAL          (default: $CLAUDE_MODEL)
CLAUDE_MODEL_WARNING           (default: $CLAUDE_MODEL)
CLAUDE_MODEL_INFO              (default: $CLAUDE_MODEL)
MAX_AGENT_ROUNDS_CRITICAL      (default: $MAX_AGENT_ROUNDS, range 0-50)
MAX_AGENT_ROUNDS_WARNING       (default: $MAX_AGENT_ROUNDS, range 0-50)
MAX_AGENT_ROUNDS_INFO          (default: $MAX_AGENT_ROUNDS, range 0-50)
                               # 0 = static-only (kein Tool-Loop)

# Phase 2 — Storm-Robustheit (alle Default = aus)
GROUP_COOLDOWN_SECONDS         (default: 0, suggested: 60)
STORM_MODE_THRESHOLD           (default: 0, suggested: 50)   # alerts/5min
STORM_MODE_NOTIFY_INTERVAL     (default: 60s)
CIRCUIT_BREAKER_THRESHOLD       (default: 0, suggested: 5)    # consecutive failures
CIRCUIT_BREAKER_OPEN_SECONDS    (default: 60)
CIRCUIT_BREAKER_MAX_PROBE_SECONDS (default: 60)               # half-open probe watchdog timeout
CIRCUIT_BREAKER_NOTIFY_INTERVAL (default: 300s)
```

**Entfernt** (Breaking Change als Teil von Phase 1, siehe 1.2): URL-basiertes Auth-Branching in `claude.go`. `API_BASE_URL` muss `x-api-key`-Auth akzeptieren. Reine OpenRouter-Standard-Endpunkte (`Authorization: Bearer`) funktionieren nicht mehr ohne Auth-Proxy davor.

Alle neuen Werte gehen durch `shared.ParseIntEnv` mit Bounds-Validation. Konfigurations-Fehler beim Startup führen zu sofortigem Exit.

## Error Handling

- **Anthropic API-Fehler (429/5xx)**: bestehender 2× Retry mit 2s/4s Backoff bleibt im `ClaudeClient`. Bei Phase-2-Aktivierung zählt der Circuit-Breaker **pro logischer Analyse** konsekutive Fehler — eine fehlgeschlagene Analyse zählt einmal, egal ob sie aus einem `Analyze`-Call oder einem 11-HTTP-Roundtrip-Tool-Loop bestand.
- **`ErrCircuitOpen` (Pipeline-Gate)**: Pipeline returned früh ohne Claude-API-Call. Fingerprint- und Group-Cooldown bleiben **gesetzt** (anders als bei API-Phase-Fehlern). Operator sieht Sammel-ntfy.
- **Failure-Phase entscheidet über Cooldown-Cleanup** (siehe 2.1 Lifecycle):
  - Pre-API (Context-Gather, Validierung) → cleart Cooldowns
  - API-Phase mit normalem Fehler → cleart Cooldowns
  - API-Phase mit `ErrCircuitOpen` → behält Cooldowns (Verstärker-Mitigation)
  - Post-API (ntfy-Publish) → behält Cooldowns (keine Re-Analyse erzwingen, Notification-Failure separat als Metrik)
- **Cache-related 4xx**: wenn Cache-Block syntaktisch falsch ist, kommt 400 zurück. Mitigation: (a) explizite Unit-Tests gegen die JSON-Struktur des Body, die die exakte Anthropic-Cache-Syntax verifizieren; (b) Integrations-Test mit `httptest.Server` der die Cache-Felder echo't; (c) Staging-Deploy bevor Production.
- **`MaxRounds=0` mit Static-only-Modus**: nur `Analyze` wird gerufen, keine Tool-Defs. Kein Risiko von Tool-Loop-Logikfehlern in dem Pfad. Cache-Breakpoint (3) — Tool-Loop-Historie — entfällt natürlich; (1) und (2) bleiben.
- **Cache-Mindestgröße nicht erreicht**: Anthropic gibt 200 zurück, aber `cache_creation_input_tokens` bleibt 0 und alle Tokens fließen als regulärer Input. Sichtbar in der neuen Metrik. Kein Fehler, nur ungenutztes Potential.

## Testing Strategy

### Unit-Tests pro Komponente

- `shared/severity_test.go` — Mappings für beide Quellen mit allen echten State-Strings (`CRITICAL`/`WARNING`/`UNKNOWN`/`OK` + `DOWN`/`UNREACHABLE`), fehlende/unbekannte Werte → `Warning`
- `shared/policy_test.go` — `ModelFor`/`MaxRoundsFor` mit/ohne Overrides, `IsDegraded()` mit/ohne StormDetector, Default-Verhalten ohne ENV-Konfiguration
- `shared/storm_test.go` — `StormDetector` mit injizierbarem `now func() time.Time`-Feld auf der Struct (kein globaler Override). Schwelle erreichen, Fenster-Rollover, Reset, Concurrent `Record()` von 100 Goroutinen unter `go test -race`
- `shared/breaker_test.go` — Zustandsübergänge closed → open → half-open → closed, plus closed → open → half-open → open (Probe-Failure). `permit.Done(nil)` resetet Counter, `permit.Done(err)` inkrementiert. `permit.IsProbe()` gibt für genau den Probe-Caller `true` zurück. **Idempotency-Test**: zweiter `Done()` ist No-Op. **Panic-Test**: Goroutine paniced nach `Acquire()` → defer-Done freigibt halfOpenInFlight, anschließend kann nächster Caller wieder Probe machen. **Probe-Watchdog-Test**: Probe blockiert > maxProbeDuration → nächster `Acquire()` während Half-Open released stuck probe und returnt ErrCircuitOpen mit state=open. **Disabled-Test**: NewCircuitBreaker(0, ...) → nil-Receiver, Acquire() returnt no-op-Permit, Done() ist no-op. Concurrency-Test: 100 parallele `Acquire()` im Half-Open-Zustand → genau einer bekommt `*Permit`, 99 bekommen `nil, ErrCircuitOpen`. `-race` Pflicht.
- `shared/cooldown_test.go` — neuer Test für `CheckAndSetGroup` und `ClearGroup` (Lifecycle), bestehende Fingerprint-Tests bleiben grün
- `shared/claude_test.go` — Cache-Marker im JSON-Body verifizieren auf allen drei Ebenen: System (letzter Block), Tools (letztes Element), Tool-Loop-Historie (letzter `tool_result` jeder Folge-Runde). Token-Counter-Increments einschließlich Cache-Read/Cache-Creation.

### Integrations-Tests (Pipeline)

In `internal/k8s/pipeline_test.go` und `internal/checkmk/pipeline_test.go`:

- Severity-Routing greift: critical nutzt `CLAUDE_MODEL_CRITICAL`, warning nutzt Fallback wenn nicht gesetzt
- `MaxRounds=0` → `Analyze` wird gerufen statt `RunToolLoop` (Mock-Client zählt beide Methoden)
- Group-Cooldown deduppliziert Alerts mit gleichem `alertname+namespace` (k8s) bzw. `host+service` (CheckMK)
- Storm-Mode forciert `rounds=0`: bei `IsDegraded() == true` ruft Pipeline `Analyze` statt `RunToolLoop` für *alle* Severities
- Half-Open-Probe forciert `rounds=0`: wenn `permit.IsProbe() == true`, gleiche Logik
- Group-Key bleibt im Storm-Mode unverändert (keine aggressivere Dedup)
- **Phase-spezifischer Cleanup**:
  - Pre-API-Failure (Mock: gather-Funktion returned error) → Cooldowns gecleared
  - API-Failure normal → Cooldowns gecleared
  - API-Failure `ErrCircuitOpen` → Cooldowns bleiben
  - Post-API-Failure (Mock: ntfy-Publish returned error) → Cooldowns bleiben

**Verstärker-Bug — Sequenztest** (kritischster Test):
1. Breaker-Threshold = 1, eine fehlgeschlagene Analyse setzt Breaker auf open via `permit.Done(err)`
2. Alert A1 mit Fingerprint F1 wird verarbeitet → `Acquire()` returned `nil, ErrCircuitOpen` → Cooldown bleibt gesetzt
3. Alert A1 mit gleichem Fingerprint F1 wird sofort nochmal vom Webhook angeliefert (Alertmanager-Retry-Simulation)
4. Erwartung: Cooldown-Hit im Handler, Pipeline wird gar nicht angefasst, Counter `alerts_cooldown_total` = 1, Mock-Claude wurde insgesamt 0× gerufen

**Half-Open-Probe-Begrenzung — Sequenztest**:
1. Breaker im Half-Open-Zustand, Probe ist noch nicht gestartet
2. Alert mit Severity=critical und konfiguriertem `MAX_AGENT_ROUNDS_CRITICAL=10`
3. Erwartung: Pipeline ruft `Analyze` (rounds=0), nicht `RunToolLoop`. Mock-Claude.Analyze zählt 1, Mock-Claude.RunToolLoop zählt 0. `permit.IsProbe() == true` für genau diesen Caller.
4. Probe-Erfolg → `permit.Done(nil)` → Breaker closed → Folge-Alert bekommt non-Probe-Permit, nutzt wieder konfigurierte Runden (`RunToolLoop` wird gerufen)
5. **Stuck-Probe-Test**: Probe-Goroutine paniced ohne Done(_) zu rufen → defer-Done freigibt halfOpenInFlight → 6 Sekunden später (`maxProbeDuration` test-konfiguriert) wird ein neuer Caller wieder erfolgreich Probe-Permit bekommen.

### Storm-Mode E2E

In `shared/server_test.go`: 100 Alerts in `Server.Enqueue`, Threshold = 50 → ab Alert 51 ist `IsDegraded()` true; Aggregator emittiert eine Sammel-ntfy. Lauf unter `-race`.

### Coverage-Gate

Repo hat bereits `coverage_extra_test.go` für >80%-Coverage. Neue Komponenten müssen entsprechend abgedeckt sein, sonst CI rot. Für die neuen Concurrency-Komponenten (StormDetector, CircuitBreaker) ist `-race` in CI Pflicht.

## Rollout

1. **Phase 1 PR mergen** → Staging-Deploy → 24-72 h beobachten:
   - Cache-Hit-Rate in Grafana sollte > 50 % nach den ersten Alerts steigen
   - Token-Verbrauch je Severity prüfen
   - Bei Bedarf `CLAUDE_MODEL_WARNING=claude-haiku-4-5` aktivieren
2. **Phase 2 PR mergen**, alle Features per Default aus
3. **Group-Cooldown** zuerst aktivieren (`GROUP_COOLDOWN_SECONDS=60`) → 1 Woche beobachten
4. **Circuit-Breaker** als zweites (`CIRCUIT_BREAKER_THRESHOLD=5`) — defensiv, schaltet sich nur unter API-Problemen ein
5. **Storm-Mode** als letztes (`STORM_MODE_THRESHOLD=50`) — größte Verhaltensänderung

## Out-of-Scope (explizit nicht in diesem Plan)

- Hartes Spend-Budget mit Kill-Switch (Anthropic-Workspace-Limit ist die externe Backstop)
- Persistierter State für Cooldown / Storm-Counter (alles in-memory, Pod-Restart resettet)
- ntfy-Side-Channel für „Budget kritisch"-Vorwarnung
- Dynamische Konfig-Reloads ohne Restart (alles via ENV beim Startup)
