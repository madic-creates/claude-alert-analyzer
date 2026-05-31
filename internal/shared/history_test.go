package shared

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
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

// flush blocks until all writes enqueued before it have been processed.
// If the store is already stopping, it returns promptly.
func (s *sqliteHistoryStore) flush() {
	done := make(chan struct{})
	select {
	case s.ch <- writeOp{done: done}:
	case <-s.stop:
		return
	}
	select {
	case <-done:
	case <-s.stop:
	}
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
		t.Error("no prior block expected with empty view.Prior")
	}
}

func TestInjectHistoryFirstFireNoSection(t *testing.T) {
	s := newTestStore(t)
	s.RecordFire(context.Background(), "fp", SeverityWarning)
	s.flush()
	actx := AnalysisContext{Sections: []ContextSection{{Name: "Existing", Content: "x"}}}
	out, _ := InjectHistory(context.Background(), s, "fp", false, actx)
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
	out, _ := InjectHistory(context.Background(), s, "fp", false, actx)
	if len(out.Sections) != 2 {
		t.Fatalf("want 2 sections, got %d", len(out.Sections))
	}
	if out.Sections[0].Name != "Alert Recurrence" {
		t.Errorf("recurrence section must be first, got %q", out.Sections[0].Name)
	}
}

func TestInjectHistoryNilStore(t *testing.T) {
	actx := AnalysisContext{Sections: []ContextSection{{Name: "Existing", Content: "x"}}}
	out, _ := InjectHistory(context.Background(), nil, "fp", false, actx)
	if len(out.Sections) != 1 {
		t.Errorf("nil store must not change sections; got %d", len(out.Sections))
	}
}

func TestLookupPriorsRoundTrip(t *testing.T) {
	s := newTestStore(t)
	s.RecordFire(context.Background(), "fp", SeverityWarning)
	s.RecordAnalysis(context.Background(), "fp", SeverityWarning, "cpu spike due to batch job")
	s.flush()

	v := s.Lookup(context.Background(), "fp")
	if len(v.Prior) != 1 {
		t.Fatalf("Prior len = %d, want 1", len(v.Prior))
	}
	p := v.Prior[0]
	if p.Summary != "cpu spike due to batch job" {
		t.Errorf("Summary = %q, want %q", p.Summary, "cpu spike due to batch job")
	}
	if p.Severity != SeverityWarning {
		t.Errorf("Severity = %v, want warning", p.Severity)
	}
	if p.At.IsZero() {
		t.Error("At must be set")
	}
}

func TestLookupPriorsMaxEntriesCap(t *testing.T) {
	s := newTestStore(t)
	s.maxEntries = 3
	for i := range 5 {
		s.RecordAnalysis(context.Background(), "fp", SeverityWarning, fmt.Sprintf("summary-%d", i))
	}
	s.flush()

	v := s.Lookup(context.Background(), "fp")
	if len(v.Prior) != 3 {
		t.Errorf("Prior len = %d, want 3 (maxEntries cap)", len(v.Prior))
	}
}

func TestLookupPriorsNewestFirst(t *testing.T) {
	s := newTestStore(t)
	base := int64(1_000_000)
	s.nowFn = func() int64 { return base }
	s.RecordAnalysis(context.Background(), "fp", SeverityWarning, "older")
	s.flush()
	s.nowFn = func() int64 { return base + 60 }
	s.RecordAnalysis(context.Background(), "fp", SeverityCritical, "newer")
	s.flush()

	v := s.Lookup(context.Background(), "fp")
	if len(v.Prior) != 2 {
		t.Fatalf("Prior len = %d, want 2", len(v.Prior))
	}
	if v.Prior[0].Summary != "newer" {
		t.Errorf("Prior[0].Summary = %q, want %q (newest first)", v.Prior[0].Summary, "newer")
	}
}

func TestLookupPriorsExcludeExpired(t *testing.T) {
	s := newTestStore(t)
	base := int64(1_000_000)
	s.nowFn = func() int64 { return base }
	s.RecordAnalysis(context.Background(), "fp", SeverityWarning, "old analysis")
	s.flush()
	// advance time past TTL (6h)
	s.nowFn = func() int64 { return base + int64((7 * time.Hour).Seconds()) }
	s.RecordFire(context.Background(), "fp", SeverityWarning) // triggers pruning on next prune interval

	v := s.Lookup(context.Background(), "fp")
	if len(v.Prior) != 0 {
		t.Errorf("Prior len = %d, want 0 (analysis outside TTL)", len(v.Prior))
	}
}

func TestHistorySectionWithPrior(t *testing.T) {
	first := time.Date(2026, 5, 30, 8, 0, 0, 0, time.UTC)
	last := time.Date(2026, 5, 30, 14, 0, 0, 0, time.UTC)
	prior := time.Date(2026, 5, 30, 10, 0, 0, 0, time.UTC)
	view := HistoryView{
		Count: 3, FirstSeen: first, LastSeen: last, Window: 6 * time.Hour,
		Prior: []PriorFinding{{At: prior, Summary: "root cause was OOM", Severity: SeverityCritical}},
	}
	sec := historySection(view, true)
	if !strings.Contains(sec.Content, "Prior analyses") {
		t.Error("injectPrior=true with non-empty Prior must include prior block")
	}
	if !strings.Contains(sec.Content, "root cause was OOM") {
		t.Errorf("prior summary not in content: %q", sec.Content)
	}
	if !strings.Contains(sec.Content, "critical") {
		t.Errorf("prior severity not in content: %q", sec.Content)
	}
	// injectPrior=false must suppress even when Prior is non-empty.
	secNoInject := historySection(view, false)
	if strings.Contains(secNoInject.Content, "Prior analyses") {
		t.Error("injectPrior=false must suppress prior block")
	}
}

func TestHumanDuration(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{6 * time.Hour, "6h"},
		{time.Hour, "1h"},
		{90 * time.Minute, "1h30m"},
		{2*time.Hour + 15*time.Minute, "2h15m"},
		{30 * time.Minute, "30m"},
		{1 * time.Minute, "1m"},
		{45 * time.Second, "1m"}, // rounds up to 1m
		{29 * time.Second, "0m"}, // rounds down to 0
	}
	for _, tc := range cases {
		got := humanDuration(tc.d)
		if got != tc.want {
			t.Errorf("humanDuration(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

func TestLoadHistoryConfigErrors(t *testing.T) {
	base := map[string]string{
		"HISTORY_ENABLED":      "",
		"HISTORY_DB_PATH":      "",
		"HISTORY_TTL":          "",
		"HISTORY_MAX_ENTRIES":  "",
		"HISTORY_INJECT_PRIOR": "",
	}
	setAll := func(t *testing.T) {
		t.Helper()
		for k, v := range base {
			t.Setenv(k, v)
		}
	}

	t.Run("invalid HISTORY_ENABLED", func(t *testing.T) {
		setAll(t)
		t.Setenv("HISTORY_ENABLED", "yes")
		if _, err := LoadHistoryConfig(); err == nil {
			t.Error("expected error for invalid HISTORY_ENABLED=yes")
		}
	})

	t.Run("invalid HISTORY_TTL format", func(t *testing.T) {
		setAll(t)
		t.Setenv("HISTORY_TTL", "not-a-duration")
		if _, err := LoadHistoryConfig(); err == nil {
			t.Error("expected error for unparseable HISTORY_TTL")
		}
	})

	t.Run("non-positive HISTORY_TTL", func(t *testing.T) {
		setAll(t)
		t.Setenv("HISTORY_TTL", "-1h")
		if _, err := LoadHistoryConfig(); err == nil {
			t.Error("expected error for negative HISTORY_TTL")
		}
	})

	t.Run("HISTORY_MAX_ENTRIES below min", func(t *testing.T) {
		setAll(t)
		t.Setenv("HISTORY_MAX_ENTRIES", "0")
		if _, err := LoadHistoryConfig(); err == nil {
			t.Error("expected error for HISTORY_MAX_ENTRIES=0 (below min of 1)")
		}
	})

	t.Run("HISTORY_MAX_ENTRIES above max", func(t *testing.T) {
		setAll(t)
		t.Setenv("HISTORY_MAX_ENTRIES", "101")
		if _, err := LoadHistoryConfig(); err == nil {
			t.Error("expected error for HISTORY_MAX_ENTRIES=101 (above max of 100)")
		}
	})

	t.Run("invalid HISTORY_INJECT_PRIOR", func(t *testing.T) {
		setAll(t)
		t.Setenv("HISTORY_INJECT_PRIOR", "maybe")
		if _, err := LoadHistoryConfig(); err == nil {
			t.Error("expected error for invalid HISTORY_INJECT_PRIOR=maybe")
		}
	})
}

func TestParseSummary(t *testing.T) {
	cases := []struct {
		name        string
		input       string
		wantSummary string
		wantBody    string
	}{
		{
			name:        "SUMMARY line on last line",
			input:       "Some analysis text.\n\nSUMMARY: root cause is X",
			wantSummary: "root cause is X",
			wantBody:    "Some analysis text.",
		},
		{
			name:        "SUMMARY line in middle last wins",
			input:       "SUMMARY: first\nmore text\nSUMMARY: last wins",
			wantSummary: "last wins",
			wantBody:    "SUMMARY: first\nmore text",
		},
		{
			name:        "SUMMARY with extra spaces",
			input:       "text\nSUMMARY:   spaced out   ",
			wantSummary: "spaced out",
			wantBody:    "text",
		},
		{
			name:        "no SUMMARY fallback to first non-heading line",
			input:       "## Heading\n\nThis is the first real line.",
			wantSummary: "This is the first real line.",
			wantBody:    "## Heading\n\nThis is the first real line.",
		},
		{
			name:        "no SUMMARY fallback truncates at 200",
			input:       strings.Repeat("x", 250),
			wantSummary: strings.Repeat("x", 200),
			wantBody:    strings.Repeat("x", 250),
		},
		{
			// 'ä' is 2 UTF-8 bytes. Byte-slicing at 200 would cut in the middle of
			// a rune; we must get exactly 200 valid runes back.
			name:        "no SUMMARY fallback truncates at 200 runes multibyte",
			input:       strings.Repeat("ä", 201),
			wantSummary: strings.Repeat("ä", 200),
			wantBody:    strings.Repeat("ä", 201),
		},
		{
			name:        "only headings returns empty summary",
			input:       "## Root cause\n### Details",
			wantSummary: "",
			wantBody:    "## Root cause\n### Details",
		},
		{
			name:        "empty input returns empty summary",
			input:       "",
			wantSummary: "",
			wantBody:    "",
		},
		{
			name:        "SUMMARY with empty value is skipped falls back to first line",
			input:       "## heading\nSUMMARY:\nSUMMARY:   \nfallback line",
			wantSummary: "fallback line",
			wantBody:    "## heading\nSUMMARY:\nSUMMARY:   \nfallback line",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotSum, gotBody := ParseSummary(tc.input)
			if gotSum != tc.wantSummary {
				t.Errorf("summary = %q, want %q", gotSum, tc.wantSummary)
			}
			if gotBody != tc.wantBody {
				t.Errorf("body = %q, want %q", gotBody, tc.wantBody)
			}
		})
	}
}

// TestNewNopHistoryStoreDirectly calls NewNopHistoryStore (0% coverage because
// callers are in other packages) and exercises all four interface methods.
func TestNewNopHistoryStoreDirectly(t *testing.T) {
	store := NewNopHistoryStore()
	store.RecordFire(context.Background(), "fp", SeverityWarning)
	store.RecordAnalysis(context.Background(), "fp", SeverityWarning, "summary")
	if v := store.Lookup(context.Background(), "fp"); v.Count != 0 {
		t.Errorf("nop Lookup Count = %d, want 0", v.Count)
	}
	if err := store.Close(); err != nil {
		t.Errorf("nop Close: %v", err)
	}
}

// TestNewHistoryStoreEnabled verifies that NewHistoryStore with Enabled=true
// delegates to newSQLiteHistoryStore and returns a working store. The
// existing TestNopHistoryStore only exercises the Enabled=false branch of
// NewHistoryStore; without this test a mutation that swapped the two return
// paths would go undetected.
func TestNewHistoryStoreEnabled(t *testing.T) {
	cfg := HistoryConfig{
		Enabled:    true,
		DBPath:     filepath.Join(t.TempDir(), "history.db"),
		TTL:        6 * time.Hour,
		MaxEntries: 5,
	}
	store, err := NewHistoryStore(cfg, ProductK8s, NewAlertMetrics(nil))
	if err != nil {
		t.Fatalf("NewHistoryStore(Enabled=true): %v", err)
	}
	if store == nil {
		t.Fatal("NewHistoryStore(Enabled=true) returned nil store")
	}
	store.RecordFire(context.Background(), "fp", SeverityInfo)
	if err := store.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestNewHistoryStoreBadDir verifies that newSQLiteHistoryStore returns a
// "create db dir" error when the parent directory cannot be created. Covers
// the os.MkdirAll failure branch in newSQLiteHistoryStore (73.3% → higher).
func TestNewHistoryStoreBadDir(t *testing.T) {
	// /dev/null is a character device, not a directory; trying to create a
	// subdirectory inside it must fail on any POSIX system.
	cfg := HistoryConfig{
		Enabled:    true,
		DBPath:     "/dev/null/sub/history.db",
		TTL:        6 * time.Hour,
		MaxEntries: 5,
	}
	_, err := newSQLiteHistoryStore(cfg, ProductK8s, NewAlertMetrics(nil))
	if err == nil {
		t.Fatal("expected error for bad db dir, got nil")
	}
	if !strings.Contains(err.Error(), "create db dir") {
		t.Errorf("error = %q, want it to mention 'create db dir'", err)
	}
}

// TestLookupAfterCloseRecordsErrorMetric verifies that Lookup on a closed
// store records alert_analyzer_history_errors_total{op="lookup"} rather than
// silently returning an empty view. Covers the QueryRowContext error branch in
// Lookup (67.9% → higher).
func TestLookupAfterCloseRecordsErrorMetric(t *testing.T) {
	prom := NewPrometheusMetricsForTest(ProductK8s)
	s := newTestStore(t)
	s.metrics = NewAlertMetrics(prom)

	// Close the store so the underlying DB is no longer open.
	// closeOnce makes the t.Cleanup call in newTestStore a no-op, so the DB
	// is not double-closed.
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s.Lookup(context.Background(), "fp")

	if got := testutil.ToFloat64(prom.HistoryErrors.WithLabelValues("lookup")); got < 1 {
		t.Errorf("HistoryErrors[lookup] = %v, want >= 1", got)
	}
}

// TestLookupPriorQueryContextErrorReturnsPartialView verifies that when the
// prior-analysis QueryContext fails, Lookup returns a partial HistoryView
// (containing the fire counts from the first query) and records the
// HistoryErrors["lookup"] metric. Covers the QueryContext error branch added
// in Cycle 93 that was previously unreachable from tests.
func TestLookupPriorQueryContextErrorReturnsPartialView(t *testing.T) {
	prom := NewPrometheusMetricsForTest(ProductK8s)
	s := newTestStore(t)
	s.metrics = NewAlertMetrics(prom)

	// Two fires so the fire-count query (QueryRowContext) succeeds with count=2,
	// then fail only the prior-analysis query (QueryContext).
	s.RecordFire(context.Background(), "fp", SeverityWarning)
	s.RecordFire(context.Background(), "fp", SeverityWarning)
	s.flush()

	wantErr := errors.New("injected prior-query error")
	old := testHookLookupPriorQueryFn
	testHookLookupPriorQueryFn = func(_ context.Context, _ string, _ ...any) (*sql.Rows, error) {
		return nil, wantErr
	}
	defer func() { testHookLookupPriorQueryFn = old }()

	view := s.Lookup(context.Background(), "fp")

	// The partial view must carry the fire count from the first query.
	if view.Count != 2 {
		t.Errorf("Count = %d, want 2 (partial view on prior-query error)", view.Count)
	}
	if len(view.Prior) != 0 {
		t.Errorf("Prior len = %d, want 0 on prior-query error", len(view.Prior))
	}
	if got := testutil.ToFloat64(prom.HistoryErrors.WithLabelValues("lookup")); got < 1 {
		t.Errorf("HistoryErrors[lookup] = %v, want >= 1", got)
	}
}

// TestLookupRowsErrRecordsMetric verifies that a rows.Err() error after the
// prior-analysis rows.Next() loop records HistoryErrors["lookup"] and logs a
// warning. Covers the rows.Err() guard added in Cycle 104 that was previously
// unreachable from tests (SQLite reads all rows into memory, so rows.Err()
// never returns an error in normal operation; the hook simulates the condition
// that other SQL drivers can trigger).
func TestLookupRowsErrRecordsMetric(t *testing.T) {
	prom := NewPrometheusMetricsForTest(ProductK8s)
	s := newTestStore(t)
	s.metrics = NewAlertMetrics(prom)

	old := testHookLookupRowsErrFn
	testHookLookupRowsErrFn = func() error {
		return errors.New("injected rows.Err()")
	}
	defer func() { testHookLookupRowsErrFn = old }()

	s.Lookup(context.Background(), "fp")

	if got := testutil.ToFloat64(prom.HistoryErrors.WithLabelValues("lookup")); got < 1 {
		t.Errorf("HistoryErrors[lookup] = %v, want >= 1", got)
	}
}

// TestPruneFailureRecordsErrorMetric verifies that prune() increments
// HistoryErrors["prune"] when the DELETE fails (closed DB). Covers the error
// branch in prune() (lines 279-280) that was previously unreachable from tests.
// pruneInterval=1 ensures prune() is triggered on the first write attempt.
func TestPruneFailureRecordsErrorMetric(t *testing.T) {
	prom := NewPrometheusMetricsForTest(ProductK8s)
	s := newTestStore(t)
	s.metrics = NewAlertMetrics(prom)
	s.pruneInterval = 1 // trigger prune after every write

	// Close only the underlying DB; the writeLoop is idle (no pending ops).
	// t.Cleanup will call s.Close() which is idempotent via closeOnce.
	if err := s.db.Close(); err != nil {
		t.Fatalf("db.Close: %v", err)
	}

	// INSERT fails (closed DB), writesSincePrune increments to 1 >= pruneInterval,
	// prune() is called, DELETE also fails → RecordHistoryError("prune").
	s.handle(writeOp{kind: "fire", fingerprint: "fp", ts: time.Now().Unix(), severity: "warning"})

	if got := testutil.ToFloat64(prom.HistoryErrors.WithLabelValues("prune")); got < 1 {
		t.Errorf("HistoryErrors[prune] = %v, want >= 1", got)
	}
}

// TestLookupSkipsAnalysisWithEmptySummary verifies that analysis rows recorded
// with an empty summary string are excluded from HistoryView.Prior. The Lookup
// path has an explicit guard (!summary.Valid || summary.String == "") that
// silently drops empty analyses; this test makes that guard observable.
func TestLookupSkipsAnalysisWithEmptySummary(t *testing.T) {
	s := newTestStore(t)
	s.RecordAnalysis(context.Background(), "fp", SeverityWarning, "") // empty — must be skipped
	s.RecordAnalysis(context.Background(), "fp", SeverityWarning, "real summary")
	s.flush()

	v := s.Lookup(context.Background(), "fp")
	if len(v.Prior) != 1 {
		t.Errorf("Prior len = %d, want 1 (empty summary must be skipped)", len(v.Prior))
	}
	if v.Prior[0].Summary != "real summary" {
		t.Errorf("Prior[0].Summary = %q, want %q", v.Prior[0].Summary, "real summary")
	}
}

// TestHandleWriteSuccessRecordsEventMetric verifies that handle() increments
// HistoryEvents["fire"] and HistoryEvents["analysis"] when INSERTs succeed.
// Calling handle() directly bypasses the write channel so the test is
// synchronous; the writeLoop goroutine has nothing queued and is idle.
func TestHandleWriteSuccessRecordsEventMetric(t *testing.T) {
	prom := NewPrometheusMetricsForTest(ProductK8s)
	s := newTestStore(t)
	s.metrics = NewAlertMetrics(prom)
	now := time.Now().Unix()

	s.handle(writeOp{kind: "fire", fingerprint: "fp", ts: now, severity: "warning"})
	s.handle(writeOp{kind: "analysis", fingerprint: "fp", ts: now, severity: "warning", summary: "root cause"})

	if got := testutil.ToFloat64(prom.HistoryEvents.WithLabelValues("fire")); got != 1 {
		t.Errorf("HistoryEvents[fire] = %v, want 1", got)
	}
	if got := testutil.ToFloat64(prom.HistoryEvents.WithLabelValues("analysis")); got != 1 {
		t.Errorf("HistoryEvents[analysis] = %v, want 1", got)
	}
	if got := testutil.ToFloat64(prom.HistoryErrors.WithLabelValues("record")); got != 0 {
		t.Errorf("HistoryErrors[record] = %v, want 0 on success", got)
	}
}

// TestHandleWriteFailureRecordsErrorMetric verifies that handle() increments
// HistoryErrors["record"] when the INSERT fails (closed DB) and does NOT
// increment HistoryEvents. Covers the error branch in handle() (lines 260-262)
// which was previously unreachable from any test.
func TestHandleWriteFailureRecordsErrorMetric(t *testing.T) {
	prom := NewPrometheusMetricsForTest(ProductK8s)
	s := newTestStore(t)
	s.metrics = NewAlertMetrics(prom)

	// Close only the underlying DB connection — the writeLoop is still running
	// but has nothing queued, so there is no concurrent access to s.db here.
	// t.Cleanup (via newTestStore) will call s.Close() which drains the channel
	// and signals the writeLoop to exit; that path is safe because no ops are
	// pending.
	if err := s.db.Close(); err != nil {
		t.Fatalf("db.Close: %v", err)
	}

	s.handle(writeOp{kind: "fire", fingerprint: "fp", ts: time.Now().Unix(), severity: "warning"})

	if got := testutil.ToFloat64(prom.HistoryErrors.WithLabelValues("record")); got < 1 {
		t.Errorf("HistoryErrors[record] = %v, want >= 1", got)
	}
	if got := testutil.ToFloat64(prom.HistoryEvents.WithLabelValues("fire")); got != 0 {
		t.Errorf("HistoryEvents[fire] = %v, want 0 on write failure", got)
	}
}
