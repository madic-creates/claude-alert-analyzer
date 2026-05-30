package shared

import (
	"context"
	"path/filepath"
	"strings"
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

func TestHistoryRecordFireNeverBlocks(t *testing.T) {
	s := newTestStore(t)
	// Block the writer by holding it on a flush that we never let complete is
	// hard; instead just enqueue far more than the channel capacity (256) and
	// assert RecordFire returns promptly for every call (drops are silent).
	done := make(chan struct{})
	go func() {
		for i := 0; i < historyWriteChanCap*4; i++ {
			s.RecordFire(context.Background(), "flood", SeverityWarning)
		}
		close(done)
	}()
	select {
	case <-done:
		// ok: all RecordFire calls returned without blocking
	case <-time.After(5 * time.Second):
		t.Fatal("RecordFire blocked — best-effort contract violated")
	}
}

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

func TestInjectHistoryNilStore(t *testing.T) {
	actx := AnalysisContext{Sections: []ContextSection{{Name: "Existing", Content: "x"}}}
	out := InjectHistory(context.Background(), nil, "fp", false, actx)
	if len(out.Sections) != 1 {
		t.Errorf("nil store must not change sections; got %d", len(out.Sections))
	}
}
