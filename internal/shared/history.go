package shared

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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
	Count     int           // kind='fire' rows within the window (incl. the current fire)
	FirstSeen time.Time     // earliest fire in window
	LastSeen  time.Time     // latest fire in window
	Window    time.Duration // the configured lookback window (for rendering)
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
