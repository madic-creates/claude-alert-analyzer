# Alert-Storm Cost & Robustness Protection — Design

**Date**: 2026-05-01
**Status**: Approved (pending implementation plan)
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

## Architecture

Drei kooperierende, aber separate Komponenten in `internal/shared/`:

1. **`AnalysisPolicy`** — dünne Decision-Schicht. Liest Severity und gibt Modell, Runden-Budget und Group-Cooldown-TTL zurück. Hält einen Read-Pointer auf den `StormDetector`, um `IsDegraded()` zu beantworten. Keine eigenen veränderlichen Felder, keine Concurrency.
2. **`StormDetector`** — Sliding-Window-Counter mit eigenem Lifecycle. Schreibt `Record()` aus dem Webhook-Handler (vor dem Enqueue), liest `Count()` aus `IsDegraded()`.
3. **`CircuitBreaker`** — eigene Komponente. Wird auf **Analyse-Ebene** in der Pipeline gegated (nicht pro HTTP-Call), damit ein Half-Open-Probe genau **eine Analyse** schützt — nicht nur den ersten HTTP-Call eines Tool-Loops. Verwaltet ihren Zustand selbst über `BeforeCall()/RecordResult(err)`.

Aufruf-Pattern in den Pipelines:

```go
// Vor jeder Analyse: Breaker-Gate auf Logical-Call-Ebene.
if err := deps.Breaker.BeforeCall(); err != nil {
    return err  // shared.ErrCircuitOpen
}

model := deps.Policy.ModelFor(alert.Severity)
rounds := deps.Policy.MaxRoundsFor(alert.Severity)

// Storm-Mode UND Half-Open-Probe forcieren beide rounds=0:
if deps.Policy.IsDegraded() || deps.Breaker.IsHalfOpenProbe() {
    rounds = 0  // static-only, kein Tool-Loop (siehe 2.2)
}

var analysis string
var err error
if rounds == 0 {
    analysis, err = deps.Claude.Analyze(ctx, model, system, user)
} else {
    analysis, _, _, err = deps.Claude.RunToolLoop(ctx, model, system, user, tools, rounds, handler)
}

deps.Breaker.RecordResult(err)
```

**Zähleinheit**: `RecordResult(err)` wird **pro logischem Analyse-Versuch** gerufen — egal ob die Analyse aus einem einzelnen `Analyze` oder einem 10-Runden `RunToolLoop` bestand. Konsekutive Fehler = konsekutive fehlgeschlagene Analysen, nicht HTTP-Roundtrips. Die internen 2×-Retries (2s/4s) im `ClaudeClient.sendRequest` bleiben unverändert und zählen nicht als separate „Fehler" für den Breaker.

**Half-Open-Semantik**: `IsHalfOpenProbe()` returned `true` für **genau eine** Analyse. Die Mutex-Gate in `BeforeCall()` markiert sie als „Probe-aktiv", `RecordResult()` resolved sie. Während dieser Probe-Analyse blockt `BeforeCall()` aller anderen Goroutinen mit `ErrCircuitOpen`.

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

`ClaudeClient` bekommt zusätzlich ein optionales `breaker *CircuitBreaker`-Feld (nil wenn deaktiviert). Wiring im Konstruktor.

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

`CooldownManager` bekommt eine zweite Methode mit eigener Map und eigenem Mutex-Pfad:

```go
func (cm *CooldownManager) CheckAndSetGroup(groupKey string, ttl time.Duration) bool
func (cm *CooldownManager) ClearGroup(groupKey string)  // für Failure-Cleanup
```

**Key-Berechnung im Handler** (Source-spezifisch, nicht in `shared`):

- `internal/k8s/handler.go`: `groupKey = labels["alertname"] + ":" + labels["namespace"]`
- `internal/checkmk/handler.go`: `groupKey = notif.Hostname + ":" + notif.ServiceDescription`

**Group-Key bleibt im Storm-Mode unverändert** — Gröberer Key wäre zu aggressiv (z.B. „CPU load" auf 50 verschiedenen Hosts → alle deduped zu einem Alert). Der Storm-Mode-Hebel ist `rounds=0`, nicht aggressivere Dedup. Wenn ein Operator gröbere Cluster-weite Dedup will, ist das eine Konfig-Entscheidung in `GROUP_COOLDOWN_SECONDS`, nicht ein automatischer Storm-Effekt.

**Lifecycle** — analog zum Fingerprint-Cooldown, mit Differenzierung nach Failure-Phase:

```
1. Fingerprint-Cooldown (bestehend) → wenn drin, fertig (no enqueue)
2. Group-Cooldown (neu, falls policy.GroupCooldownTTL > 0) → wenn drin, fertig (no enqueue)
3. Enqueue:
   - Erfolg: Cooldowns bleiben gesetzt
   - Failure (queue voll): ClearGroup(groupKey) UND Cooldown.Clear(fingerprint)
                            → Alertmanager-Retry kann durchkommen
4. Pipeline-Failure (defer): differenziert nach Phase, in der der Fehler entstand:
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

Implementierungs-Hinweis: Pipeline kapselt Phasen in benannte Funktionsschritte (`gatherContext`, `runAnalysis`, `publishNotification`) und gibt Phase-spezifische Fehler-Sentinels zurück (oder ein Phase-`enum` als Teil eines Wrapper-Errors). Der `defer` schaut auf die Phase, nicht nur auf den Fehlertyp.

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

**Concurrency-Entscheidung**: `sync.Mutex`, keine Atomics. Bucket-Rotation plus konsistenter Count-Aggregation ist mit reinen Atomics fehleranfällig (race zwischen Bucket-Wechsel und Read). Mutex ist hier billig — `Record()` läuft einmal pro eingehendem Webhook-Alert (selbst bei einem Burst maximal niedrige Hunderte pro Minute pro Analyzer).

**Wo `Record()` aufgerufen wird**: im Webhook-Handler **vor** dem Enqueue, **nach** dem Cooldown-Check. Damit zählen wir Eingangsdruck (echte neue Alerts), nicht erfolgreiche Aufnahmen — Storm-Mode greift auch dann, wenn die Queue bereits überläuft und Alerts mit 503 abgewiesen werden. Cooldown-deduplizierte Alerts zählen *nicht*, weil das System sie schon absorbiert hat.

`policy.IsDegraded()` returned `true` wenn `detector.Count() > threshold`.

**Verhalten im Degraded-Mode**:
- Pipeline setzt `rounds = 0` wenn `policy.IsDegraded()` — nur statische `Analyze`-Calls, kein Tool-Loop. Das ist der härteste Kosten- und Last-Hebel: kein Tool-Use, keine wachsende Konversationshistorie, ein einzelner Round-Trip pro Alert.
- Group-Cooldown-Key bleibt unverändert (siehe 2.1) — nicht aggressiver, um operative Risiken durch Übermäßige Cluster-Dedup zu vermeiden
- ntfy-Aggregator: pro `STORM_MODE_NOTIFY_INTERVAL` eine Sammelmeldung mit Counter und Beispiel-Alerts statt N Einzelnachrichten

Neuer Gauge `storm_mode_active{source}` (0/1) für Operator-Alerting.

ENV: `STORM_MODE_THRESHOLD=0` (Default = aus, suggested: 50), `STORM_MODE_NOTIFY_INTERVAL=60s`.

### 2.3 Anthropic Circuit-Breaker

```go
var ErrCircuitOpen = errors.New("circuit breaker open")

type CircuitBreaker struct {
    threshold       int
    openDuration    time.Duration
    now             func() time.Time

    mu              sync.Mutex
    state           breakerState   // closed | open | halfOpen
    consecFailures  int
    openedAt        time.Time
    halfOpenInFlight bool          // Mutex-Gate für die eine Probe-Analyse
}

func (b *CircuitBreaker) BeforeCall() error      // returns ErrCircuitOpen oder nil
func (b *CircuitBreaker) IsHalfOpenProbe() bool  // true für genau die eine erlaubte Probe-Analyse
func (b *CircuitBreaker) RecordResult(err error) // einmal pro Analyse, korrelierend zu BeforeCall
```

**Drei Zustände**:

- **Closed** (normal): `BeforeCall()` returned `nil`. `RecordResult(err)` mit `err != nil` inkrementiert `consecFailures`; bei Erreichen von `threshold` → Wechsel zu **open**, `openedAt = now()`. `RecordResult(nil)` resetet `consecFailures = 0`.
- **Open**: `BeforeCall()` returned `ErrCircuitOpen` solange `now() - openedAt < openDuration`. Danach Wechsel zu **half-open** beim nächsten `BeforeCall()`.
- **Half-Open**: erlaubt **genau eine** Probe-Analyse. `BeforeCall()` setzt unter Mutex `halfOpenInFlight = true` und returned `nil` für genau diesen einen Caller; alle parallelen Aufrufe in dem Zeitfenster bekommen `ErrCircuitOpen`. Während die Probe läuft, returned `IsHalfOpenProbe()` true für den Probe-Caller (Pipeline checkt das, um `rounds=0` zu erzwingen — siehe Architecture-Sektion). Probe-Result via `RecordResult()`: Erfolg → closed, `consecFailures = 0`. Failure → open, `openedAt = now()`.

**Wichtig: Gate-Ebene = Logical-Call**. `BeforeCall()/RecordResult()` werden in der Pipeline aufgerufen, **um den ganzen Tool-Loop herum**, nicht in `ClaudeClient.sendRequest`. Begründung: ein Tool-Loop ist EIN logischer API-Call; ein Half-Open-Probe soll genau eine *Analyse* zulassen, nicht den ersten HTTP-Call und dann unbegrenzt weitere innerhalb derselben Analyse durchwinken.

**Zähleinheit**: `RecordResult(err != nil)` wird **pro logischer Analyse** gerufen — egal ob `Analyze` (1 HTTP) oder `RunToolLoop` (bis zu 11 HTTP intern). Konsekutive Fehler = konsekutive fehlgeschlagene Analysen.

**Wiring in der Pipeline**: BeforeCall vor der Analyse, RecordResult danach (siehe Architecture-Sektion).

**Wichtige Verstärker-Mitigation**: Der `defer` in `pipeline.go`, der bei Fehlern `Cooldown.Clear()` und `ClearGroup` aufruft, bekommt einen Spezialfall:

```go
defer func() {
    if err != nil && !errors.Is(err, shared.ErrCircuitOpen) {
        deps.Cooldown.Clear(alert.Fingerprint)
        if groupKey != "" {
            deps.Cooldown.ClearGroup(groupKey)
        }
    }
}()
```

Damit hämmert Alertmanager bei offenem Breaker nicht weiter — Fingerprint- und Group-Cooldown bleiben aktiv und absorbieren die Last.

ntfy-Aggregator: pro `CIRCUIT_BREAKER_NOTIFY_INTERVAL` eine Sammel-Notiz „API rate-limited, n alerts pending manual review".

Neuer Gauge `claude_circuit_breaker_state{source}` (0=closed, 1=half-open, 2=open).

ENV: `CIRCUIT_BREAKER_THRESHOLD=0` (Default = aus, suggested: 5), `CIRCUIT_BREAKER_OPEN_SECONDS=60`, `CIRCUIT_BREAKER_NOTIFY_INTERVAL=300s`.

### 2.4 Storm-Mode + Circuit-Breaker — Interaktions-Matrix

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
if policy.IsDegraded() || breaker.IsHalfOpenProbe() {
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
CIRCUIT_BREAKER_THRESHOLD      (default: 0, suggested: 5)    # consecutive failures
CIRCUIT_BREAKER_OPEN_SECONDS   (default: 60)
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
- `shared/breaker_test.go` — Zustandsübergänge closed → open → half-open → closed, plus closed → open → half-open → open (Probe-Failure). `RecordResult(nil)` resetet Counter, `RecordResult(err)` inkrementiert. `IsHalfOpenProbe()` gibt für genau den Probe-Caller `true` zurück. Concurrency-Test: 100 parallele `BeforeCall()` im Half-Open-Zustand → genau einer bekommt `nil`, 99 bekommen `ErrCircuitOpen`. `-race` Pflicht.
- `shared/cooldown_test.go` — neuer Test für `CheckAndSetGroup` und `ClearGroup` (Lifecycle), bestehende Fingerprint-Tests bleiben grün
- `shared/claude_test.go` — Cache-Marker im JSON-Body verifizieren auf allen drei Ebenen: System (letzter Block), Tools (letztes Element), Tool-Loop-Historie (letzter `tool_result` jeder Folge-Runde). Token-Counter-Increments einschließlich Cache-Read/Cache-Creation.

### Integrations-Tests (Pipeline)

In `internal/k8s/pipeline_test.go` und `internal/checkmk/pipeline_test.go`:

- Severity-Routing greift: critical nutzt `CLAUDE_MODEL_CRITICAL`, warning nutzt Fallback wenn nicht gesetzt
- `MaxRounds=0` → `Analyze` wird gerufen statt `RunToolLoop` (Mock-Client zählt beide Methoden)
- Group-Cooldown deduppliziert Alerts mit gleichem `alertname+namespace` (k8s) bzw. `host+service` (CheckMK)
- Storm-Mode forciert `rounds=0`: bei `IsDegraded() == true` ruft Pipeline `Analyze` statt `RunToolLoop` für *alle* Severities
- Half-Open-Probe forciert `rounds=0`: wenn `breaker.IsHalfOpenProbe() == true`, gleiche Logik
- Group-Key bleibt im Storm-Mode unverändert (keine aggressivere Dedup)
- **Phase-spezifischer Cleanup**:
  - Pre-API-Failure (Mock: gather-Funktion returned error) → Cooldowns gecleared
  - API-Failure normal → Cooldowns gecleared
  - API-Failure `ErrCircuitOpen` → Cooldowns bleiben
  - Post-API-Failure (Mock: ntfy-Publish returned error) → Cooldowns bleiben

**Verstärker-Bug — Sequenztest** (kritischster Test):
1. Breaker-Threshold = 1, eine fehlgeschlagene Analyse setzt Breaker auf open via `RecordResult(err)`
2. Alert A1 mit Fingerprint F1 wird verarbeitet → `BeforeCall()` returned `ErrCircuitOpen` → Cooldown bleibt gesetzt
3. Alert A1 mit gleichem Fingerprint F1 wird sofort nochmal vom Webhook angeliefert (Alertmanager-Retry-Simulation)
4. Erwartung: Cooldown-Hit im Handler, Pipeline wird gar nicht angefasst, Counter `alerts_cooldown_total` = 1, Mock-Claude wurde insgesamt 0× gerufen

**Half-Open-Probe-Begrenzung — Sequenztest**:
1. Breaker im Half-Open-Zustand, Probe ist noch nicht gestartet
2. Alert mit Severity=critical und konfiguriertem `MAX_AGENT_ROUNDS_CRITICAL=10`
3. Erwartung: Pipeline ruft `Analyze` (rounds=0), nicht `RunToolLoop`. Mock-Claude.Analyze zählt 1, Mock-Claude.RunToolLoop zählt 0
4. Probe-Erfolg → Breaker closed → Folge-Alert nutzt wieder konfigurierte Runden (`RunToolLoop` wird gerufen)

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
