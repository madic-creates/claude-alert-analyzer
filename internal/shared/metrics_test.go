package shared

import (
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestAlertMetrics_InitialCountersAreZero(t *testing.T) {
	var m AlertMetrics
	if m.WebhooksReceived.Load() != 0 {
		t.Errorf("WebhooksReceived initial value = %d, want 0", m.WebhooksReceived.Load())
	}
	if m.AlertsQueued.Load() != 0 {
		t.Errorf("AlertsQueued initial value = %d, want 0", m.AlertsQueued.Load())
	}
	if m.AlertsQueueFull.Load() != 0 {
		t.Errorf("AlertsQueueFull initial value = %d, want 0", m.AlertsQueueFull.Load())
	}
	if m.AlertsCooldown.Load() != 0 {
		t.Errorf("AlertsCooldown initial value = %d, want 0", m.AlertsCooldown.Load())
	}
	if m.AlertsProcessed.Load() != 0 {
		t.Errorf("AlertsProcessed initial value = %d, want 0", m.AlertsProcessed.Load())
	}
	if m.AlertsFailed.Load() != 0 {
		t.Errorf("AlertsFailed initial value = %d, want 0", m.AlertsFailed.Load())
	}
}

func TestMetricsHandler_StatusOK(t *testing.T) {
	var m AlertMetrics
	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	m.MetricsHandler()(rr, req)
	if rr.Code != 200 {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

func TestMetricsHandler_ContentType(t *testing.T) {
	var m AlertMetrics
	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	m.MetricsHandler()(rr, req)
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want to contain text/plain", ct)
	}
	if !strings.Contains(ct, "0.0.4") {
		t.Errorf("Content-Type = %q, want to contain version 0.0.4", ct)
	}
}

func TestMetricsHandler_AllMetricNamesPresent(t *testing.T) {
	var m AlertMetrics
	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	m.MetricsHandler()(rr, req)
	body := rr.Body.String()

	names := []string{
		"alert_analyzer_webhooks_received_total",
		"alert_analyzer_alerts_queued_total",
		"alert_analyzer_alerts_queue_full_total",
		"alert_analyzer_alerts_cooldown_total",
		"alert_analyzer_alerts_processed_total",
		"alert_analyzer_alerts_failed_total",
	}
	for _, name := range names {
		if !strings.Contains(body, name) {
			t.Errorf("metric %q not found in output:\n%s", name, body)
		}
	}
}

func TestMetricsHandler_HelpAndTypeLines(t *testing.T) {
	var m AlertMetrics
	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	m.MetricsHandler()(rr, req)
	body := rr.Body.String()

	if !strings.Contains(body, "# HELP ") {
		t.Error("output should contain # HELP lines")
	}
	if !strings.Contains(body, "# TYPE ") {
		t.Error("output should contain # TYPE lines")
	}
	if !strings.Contains(body, "counter") {
		t.Error("metric types should be 'counter'")
	}
}

func TestMetricsHandler_CounterValuesReflected(t *testing.T) {
	var m AlertMetrics
	m.WebhooksReceived.Add(3)
	m.AlertsQueued.Add(2)
	m.AlertsQueueFull.Add(1)
	m.AlertsCooldown.Add(4)
	m.AlertsProcessed.Add(5)
	m.AlertsFailed.Add(1)

	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	m.MetricsHandler()(rr, req)
	body := rr.Body.String()

	checks := []string{
		"alert_analyzer_webhooks_received_total 3",
		"alert_analyzer_alerts_queued_total 2",
		"alert_analyzer_alerts_queue_full_total 1",
		"alert_analyzer_alerts_cooldown_total 4",
		"alert_analyzer_alerts_processed_total 5",
		"alert_analyzer_alerts_failed_total 1",
	}
	for _, want := range checks {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in output:\n%s", want, body)
		}
	}
}

func TestMetricsHandler_ProcessingDurationIsSummary(t *testing.T) {
	var m AlertMetrics
	m.ProcessingDurationSum.Add(5_000_000) // 5 seconds in microseconds
	m.ProcessingDurationCount.Add(3)

	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	m.MetricsHandler()(rr, req)
	body := rr.Body.String()

	// Exactly one TYPE line for the base metric name, typed as summary.
	if !strings.Contains(body, "# TYPE alert_analyzer_processing_duration_seconds summary") {
		t.Errorf("expected summary type for duration metric, got:\n%s", body)
	}
	// Sub-samples must NOT have their own TYPE or HELP lines.
	if strings.Contains(body, "# TYPE alert_analyzer_processing_duration_seconds_sum") {
		t.Errorf("_sum sub-sample must not have its own TYPE line, got:\n%s", body)
	}
	if strings.Contains(body, "# TYPE alert_analyzer_processing_duration_seconds_count") {
		t.Errorf("_count sub-sample must not have its own TYPE line, got:\n%s", body)
	}
	// Values must be present.
	if !strings.Contains(body, "alert_analyzer_processing_duration_seconds_sum 5.") {
		t.Errorf("expected _sum value in body, got:\n%s", body)
	}
	if !strings.Contains(body, "alert_analyzer_processing_duration_seconds_count 3") {
		t.Errorf("expected _count value in body, got:\n%s", body)
	}
}

func TestAlertMetrics_ConcurrentIncrements(t *testing.T) {
	var m AlertMetrics
	const n = 100
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.WebhooksReceived.Add(1)
			m.AlertsQueued.Add(1)
		}()
	}
	wg.Wait()
	if got := m.WebhooksReceived.Load(); got != n {
		t.Errorf("WebhooksReceived = %d after %d concurrent increments, want %d", got, n, n)
	}
	if got := m.AlertsQueued.Load(); got != n {
		t.Errorf("AlertsQueued = %d after %d concurrent increments, want %d", got, n, n)
	}
}
