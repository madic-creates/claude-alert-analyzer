# Alert History — Phase A (Recurrence Awareness) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist every alert fire per fingerprint in a local SQLite store and, on a re-fire, prepend an "Alert Recurrence" section ("this fingerprint has fired 3 times in the last 6h") to the Claude prompt for both analyzers.

**Architecture:** A new `shared.HistoryStore` interface with a SQLite-backed implementation (`modernc.org/sqlite`, CGO-free) and a no-op implementation. All writes go through a single background goroutine over a buffered channel, so the HTTP webhook path only does a non-blocking send. The fire is recorded in the **handler** before the cooldown gate; the recurrence lookup + prompt injection happen in the **worker** (`ProcessAlert`). Phase A writes only `kind='fire'` rows and never reads prior summaries; `RecordAnalysis` exists but is not yet called.

**Tech Stack:** Go 1.26, `database/sql` + `modernc.org/sqlite`, Prometheus client, existing `AnalysisContext`/`AlertMetrics`/config-loader patterns.

**Spec:** `docs/superpowers/specs/2026-05-30-alert-history-cross-alert-context-design.md`

---

## File Structure

- **Create** `internal/shared/history.go` — `HistoryStore` interface, `HistoryView`/`PriorFinding`, `HistoryConfig` + `LoadHistoryConfig`, `sqliteHistoryStore` (writer goroutine, schema, prune), `nopHistoryStore`, `NewHistoryStore`, `historySection`/`InjectHistory`/`humanDuration` helpers.
- **Create** `internal/shared/history_test.go` — store round-trip, count window, prune, drop-on-full, nop store, `historySection`, `InjectHistory`.
- **Modify** `internal/shared/config.go` — add `ParseDurationEnv`.
- **Modify** `internal/shared/metrics.go` — add `RecordHistoryEvent`/`RecordHistoryDrop`/`RecordHistoryError`/`ObserveRecurrence`.
- **Modify** `internal/shared/prom_metrics.go` — add history instruments + registration + pre-materialization.
- **Modify** `internal/k8s/handler.go` + `internal/checkmk/handler.go` — `HandleWebhook` gains a `history shared.HistoryStore` param; `RecordFire` before the cooldown gate.
- **Modify** `internal/k8s/pipeline.go` + `internal/checkmk/pipeline.go` — `PipelineDeps` gains `History` + `HistoryInjectPrior`; `InjectHistory` after `GatherContext`.
- **Modify** `cmd/k8s-analyzer/main.go` + `cmd/checkmk-analyzer/main.go` — load config, construct store, nil-check, pass to handler + deps, `Close` on shutdown.
- **Modify** `deploy/k8s-analyzer/{deployment,kustomization}.yaml` + **Create** `deploy/k8s-analyzer/history-pvc.yaml`.
- **Create** `deploy/checkmk-analyzer/` manifests.
- **Modify** `CLAUDE.md` + `docs/observability.md` — env vars + metrics.

---

## Task 1: Add `modernc.org/sqlite` dependency

**Files:**
- Modify: `go.mod`, `go.sum`

- [ ] **Step 1: Add the dependency**

Run: `go get modernc.org/sqlite@latest`
Expected: `go.mod` gains a `modernc.org/sqlite vX.Y.Z` line and several `modernc.org/*` indirect deps.

- [ ] **Step 2: Verify it builds**

Run: `go build ./...`
Expected: success (downloads the modernc tree on first build).

- [ ] **Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "build: add modernc.org/sqlite (CGO-free) for alert history store"
```

---

## Task 2: `ParseDurationEnv` config helper

**Files:**
- Modify: `internal/shared/config.go`
- Test: `internal/shared/config_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/shared/config_test.go` (create the file if it does not exist, with `package shared` and `import ("testing"; "time")`):

```go
func TestParseDurationEnv(t *testing.T) {
	t.Setenv("HIST_TTL", "")
	if d, err := ParseDurationEnv("HIST_TTL", 6*time.Hour); err != nil || d != 6*time.Hour {
		t.Fatalf("empty: got %v, %v; want 6h, nil", d, err)
	}
	t.Setenv("HIST_TTL", "90m")
	if d, err := ParseDurationEnv("HIST_TTL", 6*time.Hour); err != nil || d != 90*time.Minute {
		t.Fatalf("90m: got %v, %v; want 90m, nil", d, err)
	}
	t.Setenv("HIST_TTL", "nonsense")
	if _, err := ParseDurationEnv("HIST_TTL", 6*time.Hour); err == nil {
		t.Fatal("nonsense: want error, got nil")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/shared/ -run TestParseDurationEnv`
Expected: FAIL — `undefined: ParseDurationEnv`.

- [ ] **Step 3: Implement the helper**

In `internal/shared/config.go`, add `"time"` to the import block and append:

```go
// ParseDurationEnv reads a Go duration env var (e.g. "6h", "90m"). Unset or
// empty returns fallback. An unparseable value returns an error so
// misconfiguration fails fast at startup.
func ParseDurationEnv(key string, fallback time.Duration) (time.Duration, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s=%q: not a valid duration (e.g. 6h, 90m, 30s)", key, raw)
	}
	return d, nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/shared/ -run TestParseDurationEnv`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/shared/config.go internal/shared/config_test.go
git commit -m "feat(shared): add ParseDurationEnv config helper"
```

---

## Task 3: History metrics on the façade

**Files:**
- Modify: `internal/shared/prom_metrics.go`
- Modify: `internal/shared/metrics.go`

- [ ] **Step 1: Add instruments to the struct**

In `internal/shared/prom_metrics.go`, inside `type PrometheusMetrics struct`, after the `// External I/O` block add:

```go
	// Alert history
	HistoryEvents     *prometheus.CounterVec // labels: kind
	HistoryDrops      prometheus.Counter
	HistoryErrors     *prometheus.CounterVec // labels: op
	HistoryRecurrence prometheus.Histogram
```

- [ ] **Step 2: Construct and register them**

In `NewPrometheusMetrics`, after the `pm.NtfyPublishErrors = ...` block (before `reg.MustRegister(`), add:

```go
	pm.HistoryEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "alert_analyzer_history_events_total",
		Help:        "Alert-history rows written, by kind (fire|analysis).",
		ConstLabels: constLabels,
	}, []string{"kind"})

	pm.HistoryDrops = prometheus.NewCounter(prometheus.CounterOpts{
		Name:        "alert_analyzer_history_drops_total",
		Help:        "History writes dropped because the write channel was full.",
		ConstLabels: constLabels,
	})

	pm.HistoryErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "alert_analyzer_history_store_errors_total",
		Help:        "History store errors, by operation (record|lookup|prune).",
		ConstLabels: constLabels,
	}, []string{"op"})

	pm.HistoryRecurrence = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:        "alert_analyzer_history_recurrence",
		Help:        "Fire count for a fingerprint at the moment recurrence context was injected.",
		ConstLabels: constLabels,
		Buckets:     []float64{2, 3, 4, 5, 7, 10, 15, 25, 50},
	})
```

Then add them to the existing `reg.MustRegister(...)` call (append to the argument list):

```go
		pm.HistoryEvents, pm.HistoryDrops, pm.HistoryErrors, pm.HistoryRecurrence,
```

- [ ] **Step 3: Pre-materialize the label series**

In `NewPrometheusMetrics`, just before `return pm, nil`, add:

```go
	for _, kind := range []string{"fire", "analysis"} {
		pm.HistoryEvents.WithLabelValues(kind)
	}
	for _, op := range []string{"record", "lookup", "prune"} {
		pm.HistoryErrors.WithLabelValues(op)
	}
```

- [ ] **Step 4: Add façade methods**

In `internal/shared/metrics.go`, after the `// External I/O` section, append:

```go
// Alert history

func (m *AlertMetrics) RecordHistoryEvent(kind string) {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.HistoryEvents.WithLabelValues(kind).Inc()
}

func (m *AlertMetrics) RecordHistoryDrop() {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.HistoryDrops.Inc()
}

func (m *AlertMetrics) RecordHistoryError(op string) {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.HistoryErrors.WithLabelValues(op).Inc()
}

func (m *AlertMetrics) ObserveRecurrence(n int) {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.HistoryRecurrence.Observe(float64(n))
}
```

- [ ] **Step 5: Verify it builds and the metrics registry test still passes**

Run: `go test ./internal/shared/ -run TestNewPrometheusMetrics`
Expected: PASS (or, if no such test exists, run `go build ./internal/shared/` → success).

- [ ] **Step 6: Commit**

```bash
git add internal/shared/prom_metrics.go internal/shared/metrics.go
git commit -m "feat(shared): add alert-history metrics to the façade"
```

---

## Task 4: `HistoryStore` interface, types, config, nop store

**Files:**
- Create: `internal/shared/history.go`
- Test: `internal/shared/history_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/shared/history_test.go`:

```go
package shared

import (
	"context"
	"testing"
	"time"
)

func TestLoadHistoryConfigDefaults(t *testing.T) {
	for _, k := range []string{"HISTORY_ENABLED", "HISTORY_DB_PATH", "HISTORY_TTL", "HISTORY_MAX_ENTRIES", "HISTORY_INJECT_PRIOR"} {
		t.Setenv(k, "")
	}
	cfg, err := LoadHistoryConfig()
	if err != nil {
		t.Fatalf("LoadHistoryConfig: %v", err)
	}
	if cfg.Enabled {
		t.Error("Enabled should default to false")
	}
	if cfg.TTL != 6*time.Hour {
		t.Errorf("TTL = %v, want 6h", cfg.TTL)
	}
	if cfg.MaxEntries != 5 {
		t.Errorf("MaxEntries = %d, want 5", cfg.MaxEntries)
	}
	if !cfg.InjectPrior {
		t.Error("InjectPrior should default to true")
	}
	if cfg.DBPath != "/var/lib/analyzer/history.db" {
		t.Errorf("DBPath = %q", cfg.DBPath)
	}
}
```

> `TestNopHistoryStore` is added in Task 5 because it needs `NewHistoryStore`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/shared/ -run TestLoadHistoryConfig`
Expected: FAIL — `undefined: LoadHistoryConfig`.

- [ ] **Step 3: Create the file with interface, types, config, nop store**

Create `internal/shared/history.go`. This task's content builds standalone — `NewHistoryStore` and the SQLite store arrive in Task 5:

```go
package shared

import (
	"context"
	"fmt"
	"time"
)

// HistoryStore records alert fires and analyses per fingerprint and answers
// recurrence lookups. All writes are fire-and-forget (best-effort): a failure
// is logged + counted as a metric and never affects analysis. Implementations
// must be safe for concurrent use.
type HistoryStore interface {
	// RecordFire records that a fingerprint fired. Called from the HTTP handler
	// before the cooldown gate. Non-blocking; drops on a full write channel.
	RecordFire(ctx context.Context, fingerprint string, sev Severity)
	// RecordAnalysis records a completed analysis summary for a fingerprint.
	// Called from the worker after a successful analysis. Non-blocking.
	// (Wired in Phase B; present now so the interface is stable.)
	RecordAnalysis(ctx context.Context, fingerprint string, sev Severity, summary string)
	// Lookup returns recurrence info for a fingerprint over the configured
	// window. Synchronous read; returns a zero HistoryView on error.
	Lookup(ctx context.Context, fingerprint string) HistoryView
	// Close stops the writer goroutine, drains pending writes, and closes the DB.
	Close() error
}

// HistoryView is the recurrence context for a single fingerprint.
type HistoryView struct {
	Count     int            // kind='fire' rows within the window (incl. the current fire)
	FirstSeen time.Time      // earliest fire in window
	LastSeen  time.Time      // latest fire in window
	Window    time.Duration  // the configured lookback window (for rendering)
	Prior     []PriorFinding // populated in Phase B; always empty in Phase A
}

// PriorFinding is a stored analysis summary (Phase B).
type PriorFinding struct {
	At       time.Time
	Summary  string
	Severity Severity
}

// HistoryConfig is loaded from HISTORY_* env vars (see LoadHistoryConfig).
type HistoryConfig struct {
	Enabled     bool
	DBPath      string
	TTL         time.Duration
	MaxEntries  int
	InjectPrior bool
}

// LoadHistoryConfig reads the optional HISTORY_* env vars. Mirrors the
// LoadStormProtectionConfig / LoadPolicy pattern. All features default off
// (Enabled=false).
func LoadHistoryConfig() (HistoryConfig, error) {
	enabled, err := ParseBoolEnv("HISTORY_ENABLED", false)
	if err != nil {
		return HistoryConfig{}, err
	}
	ttl, err := ParseDurationEnv("HISTORY_TTL", 6*time.Hour)
	if err != nil {
		return HistoryConfig{}, err
	}
	if ttl <= 0 {
		return HistoryConfig{}, fmt.Errorf("HISTORY_TTL must be positive, got %v", ttl)
	}
	maxEntries, err := ParseIntEnv("HISTORY_MAX_ENTRIES", "5", 1, 100)
	if err != nil {
		return HistoryConfig{}, err
	}
	injectPrior, err := ParseBoolEnv("HISTORY_INJECT_PRIOR", true)
	if err != nil {
		return HistoryConfig{}, err
	}
	return HistoryConfig{
		Enabled:     enabled,
		DBPath:      EnvOrDefault("HISTORY_DB_PATH", "/var/lib/analyzer/history.db"),
		TTL:         ttl,
		MaxEntries:  maxEntries,
		InjectPrior: injectPrior,
	}, nil
}

// nopHistoryStore is used when HISTORY_ENABLED=false. Never touches disk.
type nopHistoryStore struct{}

func (nopHistoryStore) RecordFire(context.Context, string, Severity)             {}
func (nopHistoryStore) RecordAnalysis(context.Context, string, Severity, string) {}
func (nopHistoryStore) Lookup(context.Context, string) HistoryView               { return HistoryView{} }
func (nopHistoryStore) Close() error                                             { return nil }

// NewNopHistoryStore returns a no-op store. Use in tests that construct
// PipelineDeps but don't care about history.
func NewNopHistoryStore() HistoryStore { return nopHistoryStore{} }
```

> `NewHistoryStore`, `historySection`, `InjectHistory`, and `humanDuration` are added in Tasks 5 and 6.

- [ ] **Step 4: Run the config test + build the package**

Run: `go test ./internal/shared/ -run TestLoadHistoryConfig && go build ./internal/shared/`
Expected: PASS + build OK (this task is self-contained and compiles).

- [ ] **Step 5: Commit**

```bash
git add internal/shared/history.go internal/shared/history_test.go
git commit -m "feat(shared): HistoryStore interface, HistoryConfig, nop store"
```

---

## Task 5: SQLite-backed store with async writer goroutine

**Files:**
- Modify: `internal/shared/history.go`
- Test: `internal/shared/history_test.go`

- [ ] **Step 1: Write the failing tests**

Add `"path/filepath"` to the imports of `internal/shared/history_test.go`, then append:

```go
func TestNopHistoryStore(t *testing.T) {
	for _, k := range []string{"HISTORY_ENABLED", "HISTORY_DB_PATH", "HISTORY_TTL", "HISTORY_MAX_ENTRIES", "HISTORY_INJECT_PRIOR"} {
		t.Setenv(k, "")
	}
	cfg, _ := LoadHistoryConfig() // Enabled=false by default
	store, err := NewHistoryStore(cfg, ProductK8s, NewAlertMetrics(nil))
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	defer store.Close()
	store.RecordFire(context.Background(), "fp", SeverityWarning)
	if v := store.Lookup(context.Background(), "fp"); v.Count != 0 {
		t.Errorf("nop Lookup Count = %d, want 0", v.Count)
	}
}

func newTestStore(t *testing.T) *sqliteHistoryStore {
	t.Helper()
	cfg := HistoryConfig{
		Enabled:    true,
		DBPath:     filepath.Join(t.TempDir(), "history.db"),
		TTL:        6 * time.Hour,
		MaxEntries: 5,
	}
	s, err := newSQLiteHistoryStore(cfg, ProductK8s, NewAlertMetrics(nil))
	if err != nil {
		t.Fatalf("newSQLiteHistoryStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestHistoryFireRoundTrip(t *testing.T) {
	s := newTestStore(t)
	for i := 0; i < 3; i++ {
		s.RecordFire(context.Background(), "fp-1", SeverityWarning)
	}
	s.RecordFire(context.Background(), "fp-2", SeverityCritical)
	s.flush()

	v := s.Lookup(context.Background(), "fp-1")
	if v.Count != 3 {
		t.Errorf("fp-1 Count = %d, want 3", v.Count)
	}
	if v.Window != 6*time.Hour {
		t.Errorf("Window = %v, want 6h", v.Window)
	}
	if v.FirstSeen.IsZero() || v.LastSeen.IsZero() {
		t.Error("FirstSeen/LastSeen should be set")
	}
	if other := s.Lookup(context.Background(), "fp-2"); other.Count != 1 {
		t.Errorf("fp-2 Count = %d, want 1", other.Count)
	}
}

func TestHistoryCountWindow(t *testing.T) {
	s := newTestStore(t)
	base := int64(1_000_000)
	s.nowFn = func() int64 { return base }
	s.RecordFire(context.Background(), "fp", SeverityWarning) // ts = base
	s.flush()
	// Advance now well past the TTL so the earlier fire falls outside the window.
	s.nowFn = func() int64 { return base + int64((7 * time.Hour).Seconds()) }
	s.RecordFire(context.Background(), "fp", SeverityWarning) // ts = base+7h
	s.flush()

	v := s.Lookup(context.Background(), "fp")
	if v.Count != 1 {
		t.Errorf("Count = %d, want 1 (only the in-window fire)", v.Count)
	}
}

func TestHistoryPrune(t *testing.T) {
	s := newTestStore(t)
	base := int64(1_000_000)
	s.nowFn = func() int64 { return base }
	s.pruneInterval = 1 // prune after every write
	s.RecordFire(context.Background(), "old", SeverityWarning)
	s.flush()
	s.nowFn = func() int64 { return base + int64((7 * time.Hour).Seconds()) }
	s.RecordFire(context.Background(), "new", SeverityWarning)
	s.flush()

	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM alert_events WHERE fingerprint='old'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("old rows = %d, want 0 (pruned)", n)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/shared/ -run 'TestHistory|TestNopHistoryStore'`
Expected: FAIL — `undefined: newSQLiteHistoryStore`, `undefined: NewHistoryStore`, `s.flush undefined`.

- [ ] **Step 3: Expand the imports and add NewHistoryStore + the SQLite store**

First, replace the import block of `internal/shared/history.go` (currently `context`, `fmt`, `time`) with:

```go
import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)
```

(`strings` is used by `historySection` in Task 6; adding it now avoids a second import edit. If your linter rejects the unused import before Task 6, defer adding `strings` until Task 6 Step 3.)

Then add the constructor that selects between the nop and SQLite stores:

```go
// NewHistoryStore returns a nopHistoryStore when disabled, otherwise a
// SQLite-backed store. A construction failure when enabled is fatal to the
// caller (the operator explicitly asked for history).
func NewHistoryStore(cfg HistoryConfig, product Product, metrics *AlertMetrics) (HistoryStore, error) {
	if !cfg.Enabled {
		return nopHistoryStore{}, nil
	}
	return newSQLiteHistoryStore(cfg, product, metrics)
}
```

Finally append the SQLite implementation:

```go
const (
	historyWriteChanCap     = 256
	historyPruneIntervalDef = 64
	historySchemaDDL        = `
CREATE TABLE IF NOT EXISTS alert_events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  fingerprint TEXT    NOT NULL,
  ts          INTEGER NOT NULL,
  kind        TEXT    NOT NULL,
  severity    TEXT    NOT NULL,
  summary     TEXT,
  product     TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_fp_ts ON alert_events(fingerprint, ts);`
)

type writeOp struct {
	kind        string // "fire" | "analysis" | "" (flush sentinel)
	fingerprint string
	ts          int64
	severity    string
	summary     string
	done        chan struct{} // closed after the op is processed (flush only)
}

type sqliteHistoryStore struct {
	db         *sql.DB
	product    string
	ttl        time.Duration
	maxEntries int
	metrics    *AlertMetrics

	ch      chan writeOp
	stop    chan struct{} // closed by Close to signal the writer
	stopped chan struct{} // closed by the writer when it has exited

	nowFn            func() int64 // overridable in tests
	pruneInterval    int
	writesSincePrune int
}

func newSQLiteHistoryStore(cfg HistoryConfig, product Product, metrics *AlertMetrics) (*sqliteHistoryStore, error) {
	if dir := filepath.Dir(cfg.DBPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("history: create db dir %q: %w", dir, err)
		}
	}
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(DELETE)&_pragma=busy_timeout(2000)&_pragma=temp_store(MEMORY)", cfg.DBPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("history: open db: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(historySchemaDDL); err != nil {
		db.Close()
		return nil, fmt.Errorf("history: create schema: %w", err)
	}
	s := &sqliteHistoryStore{
		db:            db,
		product:       string(product),
		ttl:           cfg.TTL,
		maxEntries:    cfg.MaxEntries,
		metrics:       metrics,
		ch:            make(chan writeOp, historyWriteChanCap),
		stop:          make(chan struct{}),
		stopped:       make(chan struct{}),
		nowFn:         func() int64 { return time.Now().Unix() },
		pruneInterval: historyPruneIntervalDef,
	}
	go s.writeLoop()
	return s, nil
}

func (s *sqliteHistoryStore) RecordFire(_ context.Context, fingerprint string, sev Severity) {
	s.enqueue(writeOp{kind: "fire", fingerprint: fingerprint, ts: s.nowFn(), severity: sev.String()})
}

func (s *sqliteHistoryStore) RecordAnalysis(_ context.Context, fingerprint string, sev Severity, summary string) {
	s.enqueue(writeOp{kind: "analysis", fingerprint: fingerprint, ts: s.nowFn(), severity: sev.String(), summary: summary})
}

func (s *sqliteHistoryStore) enqueue(op writeOp) {
	select {
	case s.ch <- op:
	default:
		s.metrics.RecordHistoryDrop()
	}
}

// flush blocks until all writes enqueued before it have been processed.
// Test-only helper; safe because it just rides the same channel.
func (s *sqliteHistoryStore) flush() {
	done := make(chan struct{})
	s.ch <- writeOp{done: done}
	<-done
}

func (s *sqliteHistoryStore) writeLoop() {
	defer close(s.stopped)
	for {
		select {
		case <-s.stop:
			s.drainRemaining()
			return
		case op := <-s.ch:
			s.handle(op)
		}
	}
}

func (s *sqliteHistoryStore) drainRemaining() {
	for {
		select {
		case op := <-s.ch:
			s.handle(op)
		default:
			return
		}
	}
}

func (s *sqliteHistoryStore) handle(op writeOp) {
	if op.kind == "" { // flush sentinel
		if op.done != nil {
			close(op.done)
		}
		return
	}
	var err error
	if op.kind == "fire" {
		_, err = s.db.Exec(
			`INSERT INTO alert_events(fingerprint, ts, kind, severity, summary, product) VALUES (?, ?, 'fire', ?, NULL, ?)`,
			op.fingerprint, op.ts, op.severity, s.product)
	} else {
		_, err = s.db.Exec(
			`INSERT INTO alert_events(fingerprint, ts, kind, severity, summary, product) VALUES (?, ?, 'analysis', ?, ?, ?)`,
			op.fingerprint, op.ts, op.severity, op.summary, s.product)
	}
	if err != nil {
		s.metrics.RecordHistoryError("record")
		slog.Warn("history: write failed", "kind", op.kind, "error", err)
	} else {
		s.metrics.RecordHistoryEvent(op.kind)
	}
	s.writesSincePrune++
	if s.writesSincePrune >= s.pruneInterval {
		s.prune()
		s.writesSincePrune = 0
	}
	if op.done != nil {
		close(op.done)
	}
}

func (s *sqliteHistoryStore) prune() {
	cutoff := s.nowFn() - int64(s.ttl.Seconds())
	if _, err := s.db.Exec(`DELETE FROM alert_events WHERE ts < ?`, cutoff); err != nil {
		s.metrics.RecordHistoryError("prune")
		slog.Warn("history: prune failed", "error", err)
	}
}

func (s *sqliteHistoryStore) Lookup(ctx context.Context, fingerprint string) HistoryView {
	cutoff := s.nowFn() - int64(s.ttl.Seconds())
	var (
		count        int
		minTs, maxTs sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), MIN(ts), MAX(ts) FROM alert_events WHERE fingerprint=? AND kind='fire' AND ts >= ?`,
		fingerprint, cutoff).Scan(&count, &minTs, &maxTs)
	if err != nil {
		s.metrics.RecordHistoryError("lookup")
		slog.Warn("history: lookup failed", "error", err)
		return HistoryView{}
	}
	view := HistoryView{Count: count, Window: s.ttl}
	if minTs.Valid {
		view.FirstSeen = time.Unix(minTs.Int64, 0)
	}
	if maxTs.Valid {
		view.LastSeen = time.Unix(maxTs.Int64, 0)
	}
	// Phase B will additionally query kind='analysis' rows into view.Prior here.
	return view
}

func (s *sqliteHistoryStore) Close() error {
	close(s.stop)
	<-s.stopped
	return s.db.Close()
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/shared/ -run 'TestHistory|TestLoadHistoryConfig|TestNopHistoryStore'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/shared/history.go internal/shared/history_test.go
git commit -m "feat(shared): SQLite history store with async single-writer goroutine"
```

---

## Task 6: `historySection` + `InjectHistory` helpers

**Files:**
- Modify: `internal/shared/history.go`
- Test: `internal/shared/history_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `internal/shared/history_test.go`:

```go
func TestHistorySection(t *testing.T) {
	first := time.Date(2026, 5, 30, 8, 12, 0, 0, time.UTC)
	last := time.Date(2026, 5, 30, 14, 5, 0, 0, time.UTC)
	view := HistoryView{Count: 3, FirstSeen: first, LastSeen: last, Window: 6 * time.Hour}
	sec := historySection(view, false)
	if sec.Name != "Alert Recurrence" {
		t.Errorf("Name = %q, want %q", sec.Name, "Alert Recurrence")
	}
	if strings.HasPrefix(sec.Content, "## ") {
		t.Error("Content must not embed its own ## heading (FormatForPrompt adds it)")
	}
	if !strings.Contains(sec.Content, "fired 3 times") {
		t.Errorf("Content missing fire count: %q", sec.Content)
	}
	if !strings.Contains(sec.Content, "6h") {
		t.Errorf("Content missing window: %q", sec.Content)
	}
	if strings.Contains(sec.Content, "Prior analyses") {
		t.Error("Phase A: no prior block expected with empty view.Prior")
	}
}

func TestInjectHistoryFirstFireNoSection(t *testing.T) {
	s := newTestStore(t)
	s.RecordFire(context.Background(), "fp", SeverityWarning)
	s.flush()
	actx := AnalysisContext{Sections: []ContextSection{{Name: "Existing", Content: "x"}}}
	out := InjectHistory(context.Background(), s, "fp", false, actx)
	if len(out.Sections) != 1 || out.Sections[0].Name != "Existing" {
		t.Errorf("Count==1 must not inject a section; got %d sections", len(out.Sections))
	}
}

func TestInjectHistoryRecurrencePrepended(t *testing.T) {
	s := newTestStore(t)
	s.RecordFire(context.Background(), "fp", SeverityWarning)
	s.RecordFire(context.Background(), "fp", SeverityWarning)
	s.flush()
	actx := AnalysisContext{Sections: []ContextSection{{Name: "Existing", Content: "x"}}}
	out := InjectHistory(context.Background(), s, "fp", false, actx)
	if len(out.Sections) != 2 {
		t.Fatalf("want 2 sections, got %d", len(out.Sections))
	}
	if out.Sections[0].Name != "Alert Recurrence" {
		t.Errorf("recurrence section must be first, got %q", out.Sections[0].Name)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/shared/ -run 'TestHistorySection|TestInjectHistory'`
Expected: FAIL — `undefined: historySection`, `undefined: InjectHistory`.

- [ ] **Step 3: Implement the helpers**

Append to `internal/shared/history.go`:

```go
// InjectHistory looks up recurrence context for the alert and, if it has fired
// more than once within the window, prepends an "Alert Recurrence" section to
// actx. Best-effort: a disabled/empty store yields Count==0 and no change.
// injectPrior controls the Phase-B prior-analyses sub-block (no effect in
// Phase A, where view.Prior is always empty).
func InjectHistory(ctx context.Context, store HistoryStore, fingerprint string, injectPrior bool, actx AnalysisContext) AnalysisContext {
	if store == nil {
		return actx
	}
	view := store.Lookup(ctx, fingerprint)
	if view.Count <= 1 {
		return actx
	}
	actx.Sections = append([]ContextSection{historySection(view, injectPrior)}, actx.Sections...)
	return actx
}

func historySection(view HistoryView, injectPrior bool) ContextSection {
	var b strings.Builder
	fmt.Fprintf(&b, "This alert fingerprint has fired %d times in the last %s (first seen %s, last seen %s).",
		view.Count, humanDuration(view.Window),
		view.FirstSeen.UTC().Format("2006-01-02 15:04 MST"),
		view.LastSeen.UTC().Format("2006-01-02 15:04 MST"))
	if injectPrior && len(view.Prior) > 0 {
		b.WriteString("\n\n### Prior analyses — treat as hypotheses to verify, not established facts\n")
		for _, p := range view.Prior {
			fmt.Fprintf(&b, "- %s (%s): %s\n",
				p.At.UTC().Format("2006-01-02 15:04 MST"), p.Severity.String(), p.Summary)
		}
	}
	return ContextSection{Name: "Alert Recurrence", Content: b.String()}
}

// humanDuration renders a duration as a compact "6h" / "90m" / "1h30m" string.
func humanDuration(d time.Duration) string {
	d = d.Round(time.Minute)
	if d >= time.Hour {
		h := d / time.Hour
		m := (d % time.Hour) / time.Minute
		if m == 0 {
			return fmt.Sprintf("%dh", h)
		}
		return fmt.Sprintf("%dh%dm", h, m)
	}
	return fmt.Sprintf("%dm", d/time.Minute)
}
```

- [ ] **Step 4: Run all shared history tests**

Run: `go test ./internal/shared/ -run 'TestHistory|TestInjectHistory|TestLoadHistoryConfig|TestNopHistoryStore'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/shared/history.go internal/shared/history_test.go
git commit -m "feat(shared): historySection + InjectHistory prompt-injection helpers"
```

---

## Task 7: Inject recurrence context in the k8s pipeline

> Pipeline first (before the handler) so the tree stays buildable after every
> commit: this task only *adds* a struct field and nil-safe calls, so existing
> `main.go` (which omits the field) and existing pipeline tests (which leave it
> nil) keep compiling and passing.

**Files:**
- Modify: `internal/k8s/pipeline.go`

- [ ] **Step 1: Add the deps fields**

In `internal/k8s/pipeline.go`, inside `type PipelineDeps struct`, add (after `GatherContext`):

```go
	// History records fires/analyses and supplies recurrence context. In
	// production a non-nil store is wired in main; access here is nil-safe so
	// existing tests that omit it keep working.
	History shared.HistoryStore
	// HistoryInjectPrior gates the Phase-B prior-analyses sub-block.
	HistoryInjectPrior bool
```

- [ ] **Step 2: Inject after GatherContext (nil-safe)**

In `ProcessAlert`, replace the single line `actx := deps.GatherContext(ctx, alert)` (line 131) with:

```go
	actx := deps.GatherContext(ctx, alert)
	actx = shared.InjectHistory(ctx, deps.History, alert.Fingerprint, deps.HistoryInjectPrior, actx)
	if deps.History != nil {
		if v := deps.History.Lookup(ctx, alert.Fingerprint); v.Count > 1 {
			deps.Metrics.ObserveRecurrence(v.Count)
		}
	}
```

> `InjectHistory` is itself nil-safe (returns `actx` unchanged for a nil store), and the metric Lookup is guarded, so existing pipeline tests that don't set `History` are unaffected. The double Lookup keeps `InjectHistory` free of a metrics dependency; it's a single indexed read against a tiny table.

- [ ] **Step 3: Verify the package builds and existing tests pass**

Run: `go build ./... && go test ./internal/k8s/`
Expected: PASS, build OK (no existing test touched).

- [ ] **Step 4: Commit**

```bash
git add internal/k8s/pipeline.go
git commit -m "feat(k8s): inject recurrence context into the analysis prompt"
```

---

## Task 8: Wire the k8s handler + binary (RecordFire + store construction)

> Handler signature change and main wiring are one task: changing `HandleWebhook`'s
> arity breaks both `main.go` and existing handler-test call sites, so they are
> fixed together to leave the tree green at the end of the task.

**Files:**
- Modify: `internal/k8s/handler.go`, `internal/k8s/handler_test.go`, `cmd/k8s-analyzer/main.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/k8s/handler_test.go` a fake store and a test asserting a fire is recorded even when the cooldown suppresses the second identical alert:

```go
type fakeHistory struct{ fires int }

func (f *fakeHistory) RecordFire(context.Context, string, shared.Severity)             { f.fires++ }
func (f *fakeHistory) RecordAnalysis(context.Context, string, shared.Severity, string) {}
func (f *fakeHistory) Lookup(context.Context, string) shared.HistoryView               { return shared.HistoryView{} }
func (f *fakeHistory) Close() error                                                    { return nil }

func TestHandlerRecordsFireBeforeCooldown(t *testing.T) {
	hist := &fakeHistory{}
	cfg := Config{WebhookSecret: "s", CooldownSeconds: 300}
	cd := shared.NewCooldownManager()
	enqueue := func(shared.AlertPayload) bool { return true }
	h := HandleWebhook(cfg, cd, enqueue, shared.NewAlertMetrics(nil), nil, hist)

	body := `{"alerts":[{"fingerprint":"fp-aaa","status":"firing","labels":{"alertname":"X","severity":"warning"}}]}`
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer s")
		w := httptest.NewRecorder()
		h(w, req)
	}
	if hist.fires != 2 {
		t.Errorf("RecordFire called %d times, want 2", hist.fires)
	}
}
```

> Ensure `handler_test.go` imports include `context`, `net/http`, `net/http/httptest`, `strings`, and the `shared` package.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/k8s/ -run TestHandlerRecordsFireBeforeCooldown`
Expected: FAIL — `HandleWebhook` takes 5 args, not 6.

- [ ] **Step 3: Add the param and the RecordFire call**

In `internal/k8s/handler.go`, change the `HandleWebhook` signature to add the store as the final param:

```go
func HandleWebhook(
	cfg Config,
	cooldown *shared.CooldownManager,
	enqueue func(shared.AlertPayload) bool,
	metrics *shared.AlertMetrics,
	storm *shared.StormDetector,
	history shared.HistoryStore,
) http.HandlerFunc {
```

Then, inside the `for _, alert := range payload.Alerts` loop, immediately **before** the `groupKey := groupKeyFromLabels(alert.Labels)` line (currently line 112) and after the skip-resolved `continue` block, add:

```go
			// Record the fire before the cooldown gate so cooldown-suppressed and
			// queue-full fires are still counted. Best-effort (non-blocking).
			history.RecordFire(r.Context(), alert.Fingerprint, shared.SeverityFromAlertmanager(alert.Labels))

```

- [ ] **Step 4: Fix existing handler-test call sites**

Any existing `HandleWebhook(...)` call in `internal/k8s/handler_test.go` now has 5 args. Append `, shared.NewNopHistoryStore()` to each so they pass a non-nil store:

Run to find them: `grep -n "HandleWebhook(" internal/k8s/handler_test.go`
Edit each call (except the new `TestHandlerRecordsFireBeforeCooldown`, which already passes `hist`) to end with `, shared.NewNopHistoryStore())`.

- [ ] **Step 5: Wire `main.go` — construct the store**

In `cmd/k8s-analyzer/main.go`, after the `metrics := shared.NewAlertMetrics(prom)` line (currently line 140) and its `slog.Info("metrics initialized", ...)` block, add:

```go
	histCfg, err := shared.LoadHistoryConfig()
	if err != nil {
		slog.Error("history config", "error", err)
		os.Exit(1)
	}
	history, err := shared.NewHistoryStore(histCfg, shared.ProductK8s, metrics)
	if err != nil {
		slog.Error("history store init failed", "error", err)
		os.Exit(1)
	}
	defer history.Close()
	slog.Info("alert history", "enabled", histCfg.Enabled, "dbPath", histCfg.DBPath,
		"ttl", histCfg.TTL, "maxEntries", histCfg.MaxEntries, "injectPrior", histCfg.InjectPrior)
```

- [ ] **Step 6: Wire `main.go` — deps, nil-check, handler**

Add to the `deps := k8s.PipelineDeps{ ... }` literal (after `GatherContext: ...`):

```go
		History:            history,
		HistoryInjectPrior: histCfg.InjectPrior,
```

Extend the existing dep nil-check (lines 175-180) to include `History`:

```go
	if deps.Analyzer == nil || deps.ToolRunner == nil || deps.Policy == nil ||
		deps.Cooldown == nil || deps.Metrics == nil || deps.GatherContext == nil ||
		deps.KubectlRunner == nil || deps.Prom == nil || deps.History == nil {
		slog.Error("k8s pipeline deps incomplete — refusing to start")
		os.Exit(1)
	}
```

Change the handler construction (line 206) to pass the store:

```go
	handler := k8s.HandleWebhook(cfg, cooldownMgr, srv.Enqueue, metrics, policy.Storm, history)
```

- [ ] **Step 7: Build and run the suites**

Run: `go build ./... && go test ./internal/k8s/ ./internal/shared/`
Expected: PASS, build OK.

- [ ] **Step 8: Commit**

```bash
git add internal/k8s/handler.go internal/k8s/handler_test.go cmd/k8s-analyzer/main.go
git commit -m "feat(k8s): record fires in handler before cooldown; wire history store in main"
```

---

## Task 9: Wire the checkmk handler + pipeline + binary

**Files:**
- Modify: `internal/checkmk/handler.go`, `internal/checkmk/pipeline.go`, `cmd/checkmk-analyzer/main.go`
- Test: `internal/checkmk/handler_test.go`

- [ ] **Step 1: Write the failing handler test**

Add to `internal/checkmk/handler_test.go` (mirror the existing test style; fake store identical shape to k8s):

```go
type fakeHistory struct{ fires int }

func (f *fakeHistory) RecordFire(context.Context, string, shared.Severity)             { f.fires++ }
func (f *fakeHistory) RecordAnalysis(context.Context, string, shared.Severity, string) {}
func (f *fakeHistory) Lookup(context.Context, string) shared.HistoryView               { return shared.HistoryView{} }
func (f *fakeHistory) Close() error                                                    { return nil }

func TestHandlerRecordsFireBeforeCooldown(t *testing.T) {
	hist := &fakeHistory{}
	cfg := Config{WebhookSecret: "s", CooldownSeconds: 300}
	cd := shared.NewCooldownManager()
	enqueue := func(shared.AlertPayload) bool { return true }
	h := HandleWebhook(cfg, cd, enqueue, shared.NewAlertMetrics(nil), nil, hist)

	body := `{"hostname":"h1","service_description":"CPU","notification_type":"PROBLEM","service_state":"CRITICAL"}`
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer s")
		w := httptest.NewRecorder()
		h(w, req)
	}
	if hist.fires != 2 {
		t.Errorf("RecordFire called %d times, want 2", hist.fires)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/checkmk/ -run TestHandlerRecordsFireBeforeCooldown`
Expected: FAIL — `HandleWebhook` arg count mismatch.

- [ ] **Step 3: Add the param + call in the checkmk handler**

In `internal/checkmk/handler.go`, add `history shared.HistoryStore` as the final param of `HandleWebhook` (same as k8s). Then immediately **before** the cooldown switch (currently line 101, `switch outcome := cooldown.CheckAndSetWithGroup(...)`), after `groupKey := groupKeyFromNotif(notif)`, add:

```go
		// Record the fire before the cooldown gate (counts suppressed + queue-full
		// fires). Best-effort, non-blocking.
		history.RecordFire(r.Context(), fp, shared.SeverityFromCheckMK(notif.ServiceState, notif.HostState))

```

- [ ] **Step 4: Add deps fields + injection in the checkmk pipeline**

In `internal/checkmk/pipeline.go`, add to `PipelineDeps` (after `ValidateHost`):

```go
	History            shared.HistoryStore
	HistoryInjectPrior bool
```

Then, in `ProcessAlert`, replace the line `actx := deps.GatherContext(ctx, alert, hostInfo)` (line 142) with (nil-safe, same as k8s):

```go
	actx := deps.GatherContext(ctx, alert, hostInfo)
	actx = shared.InjectHistory(ctx, deps.History, alert.Fingerprint, deps.HistoryInjectPrior, actx)
	if deps.History != nil {
		if v := deps.History.Lookup(ctx, alert.Fingerprint); v.Count > 1 {
			deps.Metrics.ObserveRecurrence(v.Count)
		}
	}
```

(The next line, `alertContext := actx.FormatForPrompt()`, then renders the injected section.)

- [ ] **Step 4b: Fix existing checkmk handler-test call sites**

Existing `HandleWebhook(...)` calls in `internal/checkmk/handler_test.go` now have 5 args. Run `grep -n "HandleWebhook(" internal/checkmk/handler_test.go` and append `, shared.NewNopHistoryStore()` to each (except the new `TestHandlerRecordsFireBeforeCooldown`, which passes `hist`).

- [ ] **Step 5: Wire the checkmk binary**

In `cmd/checkmk-analyzer/main.go`, after `metrics := shared.NewAlertMetrics(prom)` (line 145) and its `slog.Info` block, add the same config+store construction as Task 8 Step 5 but with `shared.ProductCheckMK`:

```go
	histCfg, err := shared.LoadHistoryConfig()
	if err != nil {
		slog.Error("history config", "error", err)
		os.Exit(1)
	}
	history, err := shared.NewHistoryStore(histCfg, shared.ProductCheckMK, metrics)
	if err != nil {
		slog.Error("history store init failed", "error", err)
		os.Exit(1)
	}
	defer history.Close()
	slog.Info("alert history", "enabled", histCfg.Enabled, "dbPath", histCfg.DBPath,
		"ttl", histCfg.TTL, "maxEntries", histCfg.MaxEntries, "injectPrior", histCfg.InjectPrior)
```

Add to the `deps := checkmk.PipelineDeps{ ... }` literal:

```go
		History:            history,
		HistoryInjectPrior: histCfg.InjectPrior,
```

Extend the dep nil-check to include `deps.History == nil`. Change the handler construction (line 227) to:

```go
	handler := checkmk.HandleWebhook(cfg, cooldownMgr, srv.Enqueue, metrics, policy.Storm, history)
```

- [ ] **Step 6: Build and test everything**

Run: `go build ./... && go test ./...`
Expected: PASS, build OK.

- [ ] **Step 7: Commit**

```bash
git add internal/checkmk/handler.go internal/checkmk/handler_test.go internal/checkmk/pipeline.go cmd/checkmk-analyzer/main.go
git commit -m "feat(checkmk): record fires + inject recurrence context; wire history store"
```

---

## Task 10: k8s deployment — PVC + memory bump

**Files:**
- Create: `deploy/k8s-analyzer/history-pvc.yaml`
- Modify: `deploy/k8s-analyzer/deployment.yaml`, `deploy/k8s-analyzer/kustomization.yaml`

- [ ] **Step 1: Create the PVC**

Create `deploy/k8s-analyzer/history-pvc.yaml`:

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: claude-alert-kubernetes-analyzer-history
  namespace: monitoring
  labels:
    app.kubernetes.io/name: claude-alert-kubernetes-analyzer
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 100Mi
```

- [ ] **Step 2: Mount it + bump memory in the deployment**

In `deploy/k8s-analyzer/deployment.yaml`, change the memory limit (line 47) from `memory: 128Mi` to:

```yaml
              memory: 256Mi
```

Add a `volumeMounts` block to the `analyzer` container (after the `securityContext` block, before `livenessProbe`):

```yaml
          volumeMounts:
            - name: history
              mountPath: /var/lib/analyzer
```

Add a `volumes` block at the `spec.template.spec` level (sibling of `containers`, e.g. after the `containers:` list):

```yaml
      volumes:
        - name: history
          persistentVolumeClaim:
            claimName: claude-alert-kubernetes-analyzer-history
```

- [ ] **Step 3: Add the PVC to kustomize**

In `deploy/k8s-analyzer/kustomization.yaml`, add `history-pvc.yaml` to the `resources:` list.

- [ ] **Step 4: Validate the manifests**

Run: `kubectl kustomize deploy/k8s-analyzer/ > /dev/null && echo OK`
Expected: `OK` (no schema/render errors). If `kubectl` is unavailable, run `kustomize build deploy/k8s-analyzer/ > /dev/null && echo OK`.

- [ ] **Step 5: Commit**

```bash
git add deploy/k8s-analyzer/history-pvc.yaml deploy/k8s-analyzer/deployment.yaml deploy/k8s-analyzer/kustomization.yaml
git commit -m "deploy(k8s): add history PVC mount at /var/lib/analyzer, bump mem to 256Mi"
```

---

## Task 11: checkmk deployment manifests (new)

**Files:**
- Create: `deploy/checkmk-analyzer/deployment.yaml`, `service.yaml`, `history-pvc.yaml`, `kustomization.yaml`, `secret.example.yaml`

> The checkmk-analyzer has no manifests today. These model the k8s-analyzer set, swap the image/names, drop the in-cluster RBAC (checkmk talks to its API + SSH over the network, not the kube API), and add the SSH key secret mount and the history PVC. The operator must supply the `*-env` and `*-ssh` secrets; `secret.example.yaml` documents the keys.

- [ ] **Step 1: Create the PVC**

Create `deploy/checkmk-analyzer/history-pvc.yaml`:

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: claude-alert-checkmk-analyzer-history
  namespace: monitoring
  labels:
    app.kubernetes.io/name: claude-alert-checkmk-analyzer
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 100Mi
```

- [ ] **Step 2: Create the deployment**

Create `deploy/checkmk-analyzer/deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: claude-alert-checkmk-analyzer
  namespace: monitoring
  labels:
    app.kubernetes.io/name: claude-alert-checkmk-analyzer
spec:
  replicas: 1
  revisionHistoryLimit: 3
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app.kubernetes.io/name: claude-alert-checkmk-analyzer
  template:
    metadata:
      labels:
        app.kubernetes.io/name: claude-alert-checkmk-analyzer
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        runAsGroup: 65534
        fsGroup: 65534
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: analyzer
          image: ghcr.io/madic-creates/claude-alert-checkmk-analyzer:latest
          ports:
            - containerPort: 8080
              name: http
            - containerPort: 9101
              name: metrics
          envFrom:
            - secretRef:
                name: claude-alert-checkmk-analyzer-env
          resources:
            requests:
              cpu: 10m
              memory: 32Mi
            limits:
              cpu: 200m
              memory: 256Mi
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            - name: history
              mountPath: /var/lib/analyzer
            - name: ssh
              mountPath: /ssh
              readOnly: true
          livenessProbe:
            httpGet:
              path: /health
              port: http
            initialDelaySeconds: 3
            periodSeconds: 30
          readinessProbe:
            httpGet:
              path: /health
              port: http
            initialDelaySeconds: 2
            periodSeconds: 10
      volumes:
        - name: history
          persistentVolumeClaim:
            claimName: claude-alert-checkmk-analyzer-history
        - name: ssh
          secret:
            secretName: claude-alert-checkmk-analyzer-ssh
            defaultMode: 0400
```

- [ ] **Step 3: Create the service**

Create `deploy/checkmk-analyzer/service.yaml`:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: claude-alert-checkmk-analyzer
  namespace: monitoring
  labels:
    app.kubernetes.io/name: claude-alert-checkmk-analyzer
spec:
  selector:
    app.kubernetes.io/name: claude-alert-checkmk-analyzer
  ports:
    - name: http
      port: 8080
      targetPort: http
    - name: metrics
      port: 9101
      targetPort: metrics
```

- [ ] **Step 4: Create the example secret**

Create `deploy/checkmk-analyzer/secret.example.yaml`:

```yaml
# Copy to secret.yaml and fill in real values (do NOT commit secret.yaml).
apiVersion: v1
kind: Secret
metadata:
  name: claude-alert-checkmk-analyzer-env
  namespace: monitoring
type: Opaque
stringData:
  WEBHOOK_SECRET: "change-me"
  ANTHROPIC_API_KEY: "sk-ant-..."        # or ANTHROPIC_AUTH_TOKEN, not both
  CHECKMK_API_USER: "automation"
  CHECKMK_API_SECRET: "change-me"
  # Optional history config:
  HISTORY_ENABLED: "true"
  HISTORY_TTL: "6h"
---
# SSH key material mounted at /ssh (SSH_KEY_PATH=/ssh/id_ed25519,
# SSH_KNOWN_HOSTS_PATH=/ssh/known_hosts).
apiVersion: v1
kind: Secret
metadata:
  name: claude-alert-checkmk-analyzer-ssh
  namespace: monitoring
type: Opaque
stringData:
  id_ed25519: |
    -----BEGIN OPENSSH PRIVATE KEY-----
    change-me
    -----END OPENSSH PRIVATE KEY-----
  known_hosts: |
    host.example.com ssh-ed25519 AAAA...
```

- [ ] **Step 5: Create the kustomization**

Create `deploy/checkmk-analyzer/kustomization.yaml`:

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: monitoring
resources:
  - deployment.yaml
  - service.yaml
  - history-pvc.yaml
```

(Intentionally omits `secret.example.yaml` — operators provide their own `secret.yaml`.)

- [ ] **Step 6: Validate**

Run: `kubectl kustomize deploy/checkmk-analyzer/ > /dev/null && echo OK`
Expected: `OK`.

- [ ] **Step 7: Commit**

```bash
git add deploy/checkmk-analyzer/
git commit -m "deploy(checkmk): add deployment manifests with history PVC + SSH secret"
```

---

## Task 12: Documentation

**Files:**
- Modify: `CLAUDE.md`, `docs/observability.md`

- [ ] **Step 1: Document the env vars in CLAUDE.md**

In `CLAUDE.md`, in the "Environment Variables" section, after the storm-robustness block, add:

```markdown
Alert-history optional (default disabled): `HISTORY_ENABLED` (default `false`),
`HISTORY_DB_PATH` (default `/var/lib/analyzer/history.db`), `HISTORY_TTL`
(default `6h`, recurrence window + prune horizon), `HISTORY_MAX_ENTRIES`
(default `5`), `HISTORY_INJECT_PRIOR` (default `true`, Phase-B prior-summary
injection). Requires a writable volume at `HISTORY_DB_PATH` (PVC). Single
replica only (SQLite single-writer). See
`docs/superpowers/specs/2026-05-30-alert-history-cross-alert-context-design.md`.
```

- [ ] **Step 2: Document the metrics in docs/observability.md**

In `docs/observability.md`, in the metrics reference, add the four history metrics:

```markdown
### Alert history

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `alert_analyzer_history_events_total` | counter | `kind` (fire\|analysis) | History rows written. |
| `alert_analyzer_history_drops_total` | counter | — | Writes dropped (write channel full). |
| `alert_analyzer_history_store_errors_total` | counter | `op` (record\|lookup\|prune) | History store errors. |
| `alert_analyzer_history_recurrence` | histogram | — | Fire count at recurrence-injection time. |
```

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md docs/observability.md
git commit -m "docs: document HISTORY_* env vars and history metrics"
```

---

## Final Verification

- [ ] **Run the full suite and build:**

Run: `go build ./... && go test ./... && go vet ./...`
Expected: all PASS, no vet warnings.

- [ ] **Confirm default-disabled behavior is inert:** with no `HISTORY_*` env vars set, `LoadHistoryConfig` returns `Enabled=false` → `nopHistoryStore` → no disk access, no prompt change. (Covered by `TestNopHistoryStore`.)

---

## Phase A → Phase B handoff

Phase A ships recurrence metadata only. Phase B (separate plan) adds: the
`SUMMARY:` instruction to all four system prompts + the `runForcedSummary`
prompt, `ParseSummary` (strip-from-ntfy + heading-skipping fallback), the
`RecordAnalysis` call in both pipelines storing `RedactSecrets(summary)`, and
the `view.Prior` query in `sqliteHistoryStore.Lookup` (the `### Prior analyses`
block already renders in `historySection` when `view.Prior` is non-empty and
`injectPrior` is true).
```
