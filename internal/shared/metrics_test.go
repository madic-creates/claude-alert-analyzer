package shared

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
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
	m.ObserveContextGatherDuration(50 * time.Millisecond)
	m.SetQueueDepth(7)
	m.RecordClaudeAPIError()
	m.RecordClaudeUsage(SeverityWarning, "model-x", 1, 2, 3, 4)
	m.RecordAgentToolCall("kubectl", "ok", 50*time.Millisecond)
	m.RecordAgentRounds(3, false)
	m.SetStormMode(true)
	m.SetBreakerState(1)
	m.RecordNtfyPublishError()
	m.RecordHistoryEvent("fire")
	m.RecordHistoryDrop()
	m.RecordHistoryError("record")
	m.ObserveRecurrence(3)
	if c := m.AggregatorDropsCounter("storm"); c != nil {
		t.Errorf("AggregatorDropsCounter on nil receiver should return nil, got %v", c)
	}

	m2 := NewAlertMetrics(nil)
	m2.RecordEnqueued()
	m2.RecordDropped(DropReasonQueueFull)
	m2.RecordHistoryEvent("analysis")
	m2.RecordHistoryDrop()
	m2.RecordHistoryError("lookup")
	m2.ObserveRecurrence(2)
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

	// Agent tool-loop counters.
	m.RecordAgentToolCall("kubectl_exec", "ok", 50*time.Millisecond)
	if got := testutil.ToFloat64(prom.AgentToolCalls.WithLabelValues("kubectl_exec", "ok")); got != 1 {
		t.Errorf("AgentToolCalls[kubectl_exec,ok] = %v, want 1", got)
	}

	// Non-exhausted run: AgentRoundsExhausted must not be incremented.
	m.RecordAgentRounds(5, false)
	if got := testutil.ToFloat64(prom.AgentRoundsExhausted); got != 0 {
		t.Errorf("AgentRoundsExhausted = %v, want 0 after non-exhausted run", got)
	}

	// Exhausted run: AgentRoundsExhausted must be incremented.
	m.RecordAgentRounds(3, true)
	if got := testutil.ToFloat64(prom.AgentRoundsExhausted); got != 1 {
		t.Errorf("AgentRoundsExhausted = %v, want 1 after exhausted run", got)
	}

	// Storm-mode gauge: set to 1 when active, 0 when inactive.
	m.SetStormMode(true)
	if got := testutil.ToFloat64(prom.StormModeActive); got != 1 {
		t.Errorf("StormModeActive = %v, want 1", got)
	}
	m.SetStormMode(false)
	if got := testutil.ToFloat64(prom.StormModeActive); got != 0 {
		t.Errorf("StormModeActive = %v, want 0", got)
	}

	// Circuit-breaker state gauge.
	m.SetBreakerState(2)
	if got := testutil.ToFloat64(prom.ClaudeCircuitBreakerState); got != 2 {
		t.Errorf("ClaudeCircuitBreakerState = %v, want 2", got)
	}

	// ProcessingDuration histogram is observed via delegation.
	m.ObserveProcessingDuration(time.Second)
	var durMetric dto.Metric
	if err := prom.ProcessingDuration.Write(&durMetric); err != nil {
		t.Fatalf("ProcessingDuration.Write: %v", err)
	}
	if durMetric.Histogram.GetSampleCount() != 1 {
		t.Errorf("ProcessingDuration sample count = %d, want 1", durMetric.Histogram.GetSampleCount())
	}

	// ContextGatherDuration histogram is observed via delegation.
	m.ObserveContextGatherDuration(200 * time.Millisecond)
	var gatherMetric dto.Metric
	if err := prom.ContextGatherDuration.Write(&gatherMetric); err != nil {
		t.Fatalf("ContextGatherDuration.Write: %v", err)
	}
	if gatherMetric.Histogram.GetSampleCount() != 1 {
		t.Errorf("ContextGatherDuration sample count = %d, want 1", gatherMetric.Histogram.GetSampleCount())
	}

	// AggregatorDropsCounter returns the right labeled counter.
	dropc := m.AggregatorDropsCounter("storm")
	if dropc == nil {
		t.Fatal("AggregatorDropsCounter(\"storm\") returned nil")
	}
	dropc.Inc()
	if got := testutil.ToFloat64(prom.NotifyAggregatorDrops.WithLabelValues("storm")); got != 1 {
		t.Errorf("NotifyAggregatorDrops[storm] = %v, want 1", got)
	}

	// Alert history counters and histogram.
	m.RecordHistoryEvent("fire")
	if got := testutil.ToFloat64(prom.HistoryEvents.WithLabelValues("fire")); got != 1 {
		t.Errorf("HistoryEvents[fire] = %v, want 1", got)
	}

	m.RecordHistoryDrop()
	if got := testutil.ToFloat64(prom.HistoryDrops); got != 1 {
		t.Errorf("HistoryDrops = %v, want 1", got)
	}

	m.RecordHistoryError("record")
	if got := testutil.ToFloat64(prom.HistoryErrors.WithLabelValues("record")); got != 1 {
		t.Errorf("HistoryErrors[record] = %v, want 1", got)
	}

	m.ObserveRecurrence(5)
	var recMetric dto.Metric
	if err := prom.HistoryRecurrence.Write(&recMetric); err != nil {
		t.Fatalf("HistoryRecurrence.Write: %v", err)
	}
	if recMetric.Histogram.GetSampleCount() != 1 {
		t.Errorf("HistoryRecurrence sample count = %d, want 1", recMetric.Histogram.GetSampleCount())
	}
	if recMetric.Histogram.GetSampleSum() != 5 {
		t.Errorf("HistoryRecurrence sample sum = %v, want 5", recMetric.Histogram.GetSampleSum())
	}
}
