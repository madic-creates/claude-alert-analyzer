package shared

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestAlertMetrics_NilSafe verifies every method tolerates a nil receiver and
// a nil Prom field — the zero-value path used by tests that don't care about
// counter values.
func TestAlertMetrics_NilSafe(t *testing.T) {
	var m *AlertMetrics
	m.RecordWebhookOutcome(WebhookAccepted)
	m.RecordEnqueued()
	m.RecordDropped(DropReasonCooldown)
	m.RecordResolved()
	m.RecordProcessed(SeverityWarning)
	m.RecordFailed()
	m.ObserveProcessingDuration(100 * time.Millisecond)
	m.SetQueueDepth(7)
	m.RecordClaudeAPIError()
	m.RecordClaudeUsage(SeverityWarning, "model-x", 1, 2, 3, 4)
	m.RecordAgentToolCall("kubectl", "ok", 50*time.Millisecond)
	m.RecordAgentRounds(3, false)
	m.SetStormMode(true)
	m.SetBreakerState(1)
	m.RecordNtfyPublishError()
	if c := m.AggregatorDropsCounter("storm"); c != nil {
		t.Errorf("AggregatorDropsCounter on nil receiver should return nil, got %v", c)
	}

	m2 := NewAlertMetrics(nil)
	m2.RecordEnqueued()
	m2.RecordDropped(DropReasonQueueFull)
	if c := m2.AggregatorDropsCounter("breaker"); c != nil {
		t.Errorf("AggregatorDropsCounter with nil Prom should return nil, got %v", c)
	}
}

// TestAlertMetrics_Delegation verifies each method increments the right
// Prometheus instrument when Prom is set.
func TestAlertMetrics_Delegation(t *testing.T) {
	prom := NewPrometheusMetricsForTest(ProductK8s)
	m := NewAlertMetrics(prom)

	m.RecordEnqueued()
	if got := testutil.ToFloat64(prom.AlertsEnqueued); got != 1 {
		t.Errorf("AlertsEnqueued = %v, want 1", got)
	}

	m.RecordDropped(DropReasonCooldown)
	if got := testutil.ToFloat64(prom.AlertsDropped.WithLabelValues("cooldown")); got != 1 {
		t.Errorf("AlertsDropped[cooldown] = %v, want 1", got)
	}

	m.RecordResolved()
	if got := testutil.ToFloat64(prom.AlertsResolved); got != 1 {
		t.Errorf("AlertsResolved = %v, want 1", got)
	}

	m.RecordProcessed(SeverityCritical)
	if got := testutil.ToFloat64(prom.AlertsProcessed.WithLabelValues("critical")); got != 1 {
		t.Errorf("AlertsProcessed[critical] = %v, want 1", got)
	}

	m.RecordFailed()
	if got := testutil.ToFloat64(prom.AlertsFailed); got != 1 {
		t.Errorf("AlertsFailed = %v, want 1", got)
	}

	m.RecordWebhookOutcome(WebhookAccepted)
	if got := testutil.ToFloat64(prom.WebhooksTotal.WithLabelValues("accepted")); got != 1 {
		t.Errorf("WebhooksTotal[accepted] = %v, want 1", got)
	}

	m.RecordClaudeUsage(SeverityWarning, "claude-sonnet", 100, 50, 200, 75)
	if got := testutil.ToFloat64(prom.ClaudeTokens.WithLabelValues("input", "warning", "claude-sonnet")); got != 100 {
		t.Errorf("ClaudeTokens[input,warning,claude-sonnet] = %v, want 100", got)
	}

	m.SetQueueDepth(42)
	if got := testutil.ToFloat64(prom.QueueDepth); got != 42 {
		t.Errorf("QueueDepth = %v, want 42", got)
	}

	m.RecordClaudeAPIError()
	if got := testutil.ToFloat64(prom.ClaudeAPIErrors); got != 1 {
		t.Errorf("ClaudeAPIErrors = %v, want 1", got)
	}

	m.RecordNtfyPublishError()
	if got := testutil.ToFloat64(prom.NtfyPublishErrors); got != 1 {
		t.Errorf("NtfyPublishErrors = %v, want 1", got)
	}
}
