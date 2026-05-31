package shared

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
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
	Prior     []PriorFinding // recent analysis summaries, newest first; empty if none recorded
}

// PriorFinding is a stored analysis summary.
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

// testHookLookupPriorQueryFn, if non-nil, replaces s.db.QueryContext in the
// Lookup prior-analysis sub-query. Nil in production.
var testHookLookupPriorQueryFn func(context.Context, string, ...any) (*sql.Rows, error)

// testHookLookupRowsErrFn, if non-nil, is called after the prior-analysis
// rows.Next() loop instead of rows.Err(). Nil in production.
var testHookLookupRowsErrFn func() error

// nopHistoryStore is used when HISTORY_ENABLED=false. Never touches disk.
type nopHistoryStore struct{}

func (nopHistoryStore) RecordFire(context.Context, string, Severity)             {}
func (nopHistoryStore) RecordAnalysis(context.Context, string, Severity, string) {}
func (nopHistoryStore) Lookup(context.Context, string) HistoryView               { return HistoryView{} }
func (nopHistoryStore) Close() error                                             { return nil }

// NewNopHistoryStore returns a no-op store. Use in tests that construct
// PipelineDeps but don't care about history.
func NewNopHistoryStore() HistoryStore { return nopHistoryStore{} }

// NewHistoryStore returns a nopHistoryStore when disabled, otherwise a
// SQLite-backed store. A construction failure when enabled is fatal to the
// caller (the operator explicitly asked for history).
func NewHistoryStore(cfg HistoryConfig, product Product, metrics *AlertMetrics) (HistoryStore, error) {
	if !cfg.Enabled {
		return nopHistoryStore{}, nil
	}
	return newSQLiteHistoryStore(cfg, product, metrics)
}

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

	ch        chan writeOp
	stop      chan struct{} // closed by Close to signal the writer
	stopped   chan struct{} // closed by the writer when it has exited
	closeOnce sync.Once

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
		_ = db.Close()
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

	// Populate Prior from kind='analysis' rows, newest first.
	priorQuery := s.db.QueryContext
	if testHookLookupPriorQueryFn != nil {
		priorQuery = testHookLookupPriorQueryFn
	}
	rows, err := priorQuery(ctx,
		`SELECT ts, summary, severity FROM alert_events WHERE fingerprint=? AND kind='analysis' AND ts >= ? ORDER BY ts DESC LIMIT ?`,
		fingerprint, cutoff, s.maxEntries)
	if err != nil {
		s.metrics.RecordHistoryError("lookup")
		slog.Warn("history: prior lookup failed", "error", err)
		return view
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			ts            int64
			summary       sql.NullString
			severityLabel string
		)
		if err := rows.Scan(&ts, &summary, &severityLabel); err != nil {
			slog.Warn("history: scan prior row failed", "error", err)
			continue
		}
		if !summary.Valid || summary.String == "" {
			continue
		}
		view.Prior = append(view.Prior, PriorFinding{
			At:       time.Unix(ts, 0),
			Summary:  summary.String,
			Severity: parseSeverity(severityLabel),
		})
	}
	rowsErrFn := (*sql.Rows).Err
	if testHookLookupRowsErrFn != nil {
		rowsErrFn = func(_ *sql.Rows) error { return testHookLookupRowsErrFn() }
	}
	if err := rowsErrFn(rows); err != nil {
		s.metrics.RecordHistoryError("lookup")
		slog.Warn("history: prior rows iteration failed", "error", err)
	}
	return view
}

func (s *sqliteHistoryStore) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.stop)
		<-s.stopped
		err = s.db.Close()
	})
	return err
}

// InjectHistory looks up recurrence context for the alert and, if it has fired
// more than once within the window, prepends an "Alert Recurrence" section to
// actx. Returns the (possibly modified) context and the HistoryView from the
// single Lookup so callers can use the view (e.g. to record a metric) without
// a second round-trip. Best-effort: a nil/disabled/empty store yields a zero
// HistoryView and no context change. injectPrior controls the prior-analyses
// sub-block (it has no effect when view.Prior is empty).
func InjectHistory(ctx context.Context, store HistoryStore, fingerprint string, injectPrior bool, actx AnalysisContext) (AnalysisContext, HistoryView) {
	if store == nil {
		return actx, HistoryView{}
	}
	view := store.Lookup(ctx, fingerprint)
	if view.Count <= 1 {
		return actx, view
	}
	actx.Sections = append([]ContextSection{historySection(view, injectPrior)}, actx.Sections...)
	return actx, view
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

// ParseSummary extracts a one-line summary from a Claude analysis response for
// storage in the history DB. It returns the extracted summary and a body
// suitable for ntfy publication (SUMMARY: line removed).
//
// Search order: find the LAST line matching "SUMMARY: …" (case-sensitive).
// If found: summary = the text after "SUMMARY: ", body = text with that line
// stripped. If absent: fall back to the first non-empty, non-Markdown-heading
// line, truncated to 200 chars; body = original text unchanged. If no usable
// line exists summary is "" and the caller should skip RecordAnalysis (better
// no history entry than a misleading heading stored as a hypothesis).
func ParseSummary(text string) (summary, body string) {
	const prefix = "SUMMARY:"
	lines := strings.Split(text, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])
		if strings.HasPrefix(trimmed, prefix) {
			rest := strings.TrimSpace(strings.TrimPrefix(trimmed, prefix))
			if rest == "" {
				continue
			}
			kept := make([]string, 0, len(lines)-1)
			kept = append(kept, lines[:i]...)
			kept = append(kept, lines[i+1:]...)
			return rest, strings.TrimRight(strings.Join(kept, "\n"), "\n")
		}
	}
	// Fallback: first non-empty, non-heading, non-SUMMARY line.
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, prefix) {
			continue
		}
		if runes := []rune(trimmed); len(runes) > 200 {
			trimmed = string(runes[:200])
		}
		return trimmed, text
	}
	return "", text
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
