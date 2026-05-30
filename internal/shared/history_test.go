package shared

import (
	"context"
	"path/filepath"
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
