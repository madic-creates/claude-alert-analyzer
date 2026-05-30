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
