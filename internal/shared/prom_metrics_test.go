package shared

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestNewPrometheusMetrics_PrematerializedSeries verifies that bounded label
// combinations exist as zero-valued time series immediately after construction,
// so dashboard queries like rate(alert_analyzer_webhooks_total[5m]) return 0
// instead of "no data" before the first event arrives. CounterVec is lazy by
// default: a series only materializes on the first WithLabelValues(...) call.
func TestNewPrometheusMetrics_PrematerializedSeries(t *testing.T) {
	pm := NewPrometheusMetricsForTest(ProductK8s)

	cases := []struct {
		name string
		got  int
		want int
	}{
		{"WebhooksTotal (6 outcomes)", testutil.CollectAndCount(pm.WebhooksTotal), 6},
		{"AlertsDropped (4 reasons)", testutil.CollectAndCount(pm.AlertsDropped), 4},
		{"AlertsProcessed (4 severities)", testutil.CollectAndCount(pm.AlertsProcessed), 4},
		{"NotifyAggregatorDrops (2 aggregators)", testutil.CollectAndCount(pm.NotifyAggregatorDrops), 2},
		{"AgentToolCalls (3 tools x 7 outcomes)", testutil.CollectAndCount(pm.AgentToolCalls), 21},
		{"AgentToolDuration (3 tools)", testutil.CollectAndCount(pm.AgentToolDuration), 3},
		{"HistoryEvents (2 kinds)", testutil.CollectAndCount(pm.HistoryEvents), 2},
		{"HistoryErrors (3 ops)", testutil.CollectAndCount(pm.HistoryErrors), 3},
		{"HistoryLookups (2 results)", testutil.CollectAndCount(pm.HistoryLookups), 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.got != c.want {
				t.Errorf("series count = %d, want %d", c.got, c.want)
			}
		})
	}

	// Verify each WebhookOutcome value is materialized at zero
	for _, outcome := range []WebhookOutcome{
		WebhookAccepted, WebhookAuthFailed, WebhookPayloadInvalid,
		WebhookPayloadTooLarge, WebhookUnavailable, WebhookInternalError,
	} {
		v := testutil.ToFloat64(pm.WebhooksTotal.WithLabelValues(string(outcome)))
		if v != 0 {
			t.Errorf("WebhooksTotal[outcome=%q] = %v, want 0 (zero-materialized)", outcome, v)
		}
	}

	// Verify each DropReason value is materialized at zero
	for _, reason := range []DropReason{
		DropReasonInvalidFingerprint, DropReasonCooldown,
		DropReasonGroupCooldown, DropReasonQueueFull,
	} {
		v := testutil.ToFloat64(pm.AlertsDropped.WithLabelValues(string(reason)))
		if v != 0 {
			t.Errorf("AlertsDropped[reason=%q] = %v, want 0", reason, v)
		}
	}

	// Verify each Severity value is materialized at zero
	for _, sev := range []Severity{SeverityUnknown, SeverityInfo, SeverityWarning, SeverityCritical} {
		v := testutil.ToFloat64(pm.AlertsProcessed.WithLabelValues(sev.String()))
		if v != 0 {
			t.Errorf("AlertsProcessed[severity=%q] = %v, want 0", sev, v)
		}
	}

	// Verify each HistoryEvents kind is materialized at zero
	for _, kind := range []string{"fire", "analysis"} {
		v := testutil.ToFloat64(pm.HistoryEvents.WithLabelValues(kind))
		if v != 0 {
			t.Errorf("HistoryEvents[kind=%q] = %v, want 0 (zero-materialized)", kind, v)
		}
	}

	// Verify each HistoryErrors op is materialized at zero
	for _, op := range []string{"record", "lookup", "prune"} {
		v := testutil.ToFloat64(pm.HistoryErrors.WithLabelValues(op))
		if v != 0 {
			t.Errorf("HistoryErrors[op=%q] = %v, want 0 (zero-materialized)", op, v)
		}
	}

	// Verify each HistoryLookups result is materialized at zero
	for _, result := range []string{"hit", "miss"} {
		v := testutil.ToFloat64(pm.HistoryLookups.WithLabelValues(result))
		if v != 0 {
			t.Errorf("HistoryLookups[result=%q] = %v, want 0 (zero-materialized)", result, v)
		}
	}
}

// TestMaterializeClaudeTokensForModels verifies that the dynamic-model
// materialization API populates kind × severity × model series at zero so
// dashboard queries return 0 instead of "no data" before the first Claude
// call.
func TestMaterializeClaudeTokensForModels(t *testing.T) {
	pm := NewPrometheusMetricsForTest(ProductK8s)

	// Before: no claude_tokens series
	if got := testutil.CollectAndCount(pm.ClaudeTokens); got != 0 {
		t.Errorf("ClaudeTokens series before MaterializeClaudeTokensForModels = %d, want 0", got)
	}

	pm.MaterializeClaudeTokensForModels([]string{"claude-opus-4-7", "claude-haiku-4-5"})

	// After: 4 kinds × 4 severities × 2 models = 32
	if got := testutil.CollectAndCount(pm.ClaudeTokens); got != 32 {
		t.Errorf("ClaudeTokens series after = %d, want 32 (4 kinds x 4 severities x 2 models)", got)
	}

	// Empty model strings are skipped
	pmEmpty := NewPrometheusMetricsForTest(ProductK8s)
	pmEmpty.MaterializeClaudeTokensForModels([]string{"", "claude-opus-4-7", ""})
	if got := testutil.CollectAndCount(pmEmpty.ClaudeTokens); got != 16 {
		t.Errorf("ClaudeTokens with empty models filtered = %d, want 16 (4x4x1)", got)
	}

	// Idempotent
	pm.MaterializeClaudeTokensForModels([]string{"claude-opus-4-7", "claude-haiku-4-5"})
	if got := testutil.CollectAndCount(pm.ClaudeTokens); got != 32 {
		t.Errorf("ClaudeTokens after second call = %d, want 32 (idempotent)", got)
	}

	// Nil receiver is a no-op
	var nilPM *PrometheusMetrics
	nilPM.MaterializeClaudeTokensForModels([]string{"x"}) // must not panic
}

// TestAnalysisPolicy_AllModels verifies the helper used by cmd/* to feed
// MaterializeClaudeTokensForModels.
func TestAnalysisPolicy_AllModels(t *testing.T) {
	p := &AnalysisPolicy{
		DefaultModel: "claude-opus-4-7",
		ModelOverrides: map[Severity]string{
			SeverityCritical: "claude-opus-4-7", // dup of default — must not appear twice
			SeverityWarning:  "claude-haiku-4-5",
			SeverityInfo:     "", // empty — must be skipped
		},
	}
	got := p.AllModels()
	if len(got) != 2 {
		t.Errorf("AllModels = %v, want 2 unique entries", got)
	}
	seen := map[string]bool{}
	for _, m := range got {
		seen[m] = true
	}
	if !seen["claude-opus-4-7"] || !seen["claude-haiku-4-5"] {
		t.Errorf("AllModels missing expected models: %v", got)
	}
}

// TestNewPrometheusMetricsForTest_PanicsOnInvalidProduct verifies that
// NewPrometheusMetricsForTest panics (rather than silently returning nil) when
// given an unrecognized Product value. The panic is intentional: it surfaces
// test-setup mistakes at construction time instead of producing a nil-pointer
// dereference later in the test, making the failure location immediately obvious.
func TestNewPrometheusMetricsForTest_PanicsOnInvalidProduct(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for invalid product, got none")
		}
	}()
	NewPrometheusMetricsForTest(Product("bogus"))
}
