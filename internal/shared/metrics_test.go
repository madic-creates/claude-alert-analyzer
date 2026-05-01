package shared

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
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
		"alert_analyzer_alerts_invalid_fingerprint_total",
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
	m.AlertsInvalidFingerprint.Add(2)

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
		"alert_analyzer_alerts_invalid_fingerprint_total 2",
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

// TestMetricsHandler_WithPrometheusMetrics_IncludesLabeledMetrics verifies that
// when Prom is non-nil, MetricsHandler appends labeled Prometheus metrics to the
// output. This exercises NewPrometheusMetrics, Registry, all Record* helpers,
// the m.Prom != nil branch of MetricsHandler, and the bufferedResponseWriter
// helper (Header, WriteHeader, Write).
func TestMetricsHandler_WithPrometheusMetrics_IncludesLabeledMetrics(t *testing.T) {
	m := &AlertMetrics{Prom: NewPrometheusMetrics()}
	m.RecordAnalyzed("k8s", "critical")
	m.RecordCooldown("k8s")
	m.SetQueueDepth("k8s", 3)
	m.Prom.ClaudeAPIDuration.WithLabelValues("k8s").Observe(1.5)
	m.RecordClaudeAPIError("k8s")
	m.RecordNtfyPublishError("k8s")

	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	m.MetricsHandler()(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()

	wantMetrics := []string{
		"alerts_analyzed_total",
		"alerts_cooldown_total",
		"queue_depth",
		"claude_api_duration_seconds",
		"claude_api_errors_total",
		"ntfy_publish_errors_total",
	}
	for _, name := range wantMetrics {
		if !strings.Contains(body, name) {
			t.Errorf("labeled metric %q not found in output:\n%s", name, body)
		}
	}

	// Verify counter values recorded via the helpers appear in the output.
	if !strings.Contains(body, `alerts_analyzed_total{severity="critical",source="k8s"} 1`) {
		t.Errorf("expected alerts_analyzed_total counter with value 1, got:\n%s", body)
	}
	if !strings.Contains(body, `alerts_cooldown_total{source="k8s"} 1`) {
		t.Errorf("expected alerts_cooldown_total counter with value 1, got:\n%s", body)
	}
	if !strings.Contains(body, `claude_api_errors_total{source="k8s"} 1`) {
		t.Errorf("expected claude_api_errors_total counter with value 1, got:\n%s", body)
	}
	if !strings.Contains(body, `ntfy_publish_errors_total{source="k8s"} 1`) {
		t.Errorf("expected ntfy_publish_errors_total counter with value 1, got:\n%s", body)
	}
}

// TestWithPrometheusMetrics_RecordsCallDuration verifies that WithPrometheusMetrics
// wires the durationHistogram so that a successful API call records an observation.
func TestWithPrometheusMetrics_RecordsCallDuration(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"content":[{"type":"text","text":"analysis"}],"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":5}}`)
	}))
	defer srv.Close()

	m := &AlertMetrics{Prom: NewPrometheusMetrics()}
	client := &ClaudeClient{
		HTTP:    srv.Client(),
		BaseURL: srv.URL,
		APIKey:  "test-key",
		Model:   "claude-test",
	}
	client.WithPrometheusMetrics(m, "k8s")

	_, err := client.Analyze(context.Background(), "test-model", "system", "user")
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}

	// The histogram should have exactly one observation recorded.
	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	m.MetricsHandler()(rr, req)
	body := rr.Body.String()

	if !strings.Contains(body, `claude_api_duration_seconds_count{source="k8s"} 1`) {
		t.Errorf("expected claude_api_duration_seconds_count{source=\"k8s\"} 1 in output, got:\n%s", body)
	}
	// Verify that at least one custom bucket boundary (120 s) is present. The
	// default prometheus.DefBuckets cap at 10 s and would not contain "le=\"120\"";
	// finding it confirms the Claude-specific bucket set is in use.
	if !strings.Contains(body, `le="120"`) {
		t.Errorf("expected custom bucket le=\"120\" in histogram output, got:\n%s", body)
	}
}

// TestBufferedResponseWriter_WriteHeader verifies that WriteHeader stores the
// status code so that callers can inspect it after promhttp finishes writing.
// In the normal success path promhttp never calls WriteHeader (it only calls
// Write), so this method is exercised here directly to ensure the interface
// contract is satisfied and the stored code is retrievable.
func TestBufferedResponseWriter_WriteHeader(t *testing.T) {
	var buf bytes.Buffer
	brw := newBufferedResponseWriter(&buf)
	brw.WriteHeader(http.StatusInternalServerError)
	if brw.code != http.StatusInternalServerError {
		t.Errorf("WriteHeader(%d) stored code %d, want %d",
			http.StatusInternalServerError, brw.code, http.StatusInternalServerError)
	}
}

// TestMetricsHandlerWith_PromHandlerNon200_ExcludesErrorBody verifies that
// when a promhttp-like handler signals an error by calling WriteHeader with a
// non-200 status code, MetricsHandler omits the error body from the response
// rather than appending it to the valid Prometheus text. Appending an HTTP
// error body would produce invalid Prometheus exposition format and cause
// scrapers to reject the entire /metrics response.
func TestMetricsHandlerWith_PromHandlerNon200_ExcludesErrorBody(t *testing.T) {
	var m AlertMetrics
	const errBody = "prometheus gather error: some registry fault"

	// Simulate a promhttp handler that encounters a gather error.
	errHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, errBody)
	})

	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	m.metricsHandlerWith(errHandler)(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("outer response status = %d, want 200 (hand-rolled metrics must still be served)", rr.Code)
	}
	body := rr.Body.String()

	// The error body written by the failing promHandler must NOT appear.
	if strings.Contains(body, errBody) {
		t.Errorf("error body from failing promhttp handler leaked into output:\n%s", body)
	}
	// Hand-rolled metrics must still be present despite the promHandler error.
	if !strings.Contains(body, "alert_analyzer_webhooks_received_total") {
		t.Errorf("hand-rolled metrics missing from output after promHandler error:\n%s", body)
	}
}

// TestMetricsHandlerWith_PromHandler200_IncludesOutput verifies that when the
// injected handler explicitly calls WriteHeader(200), its output is still
// included (covers the bw.code == http.StatusOK branch).
func TestMetricsHandlerWith_PromHandler200_IncludesOutput(t *testing.T) {
	var m AlertMetrics
	const promBody = "# some_metric 1\n"

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, promBody)
	})

	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	m.metricsHandlerWith(okHandler)(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, promBody) {
		t.Errorf("expected promHandler output in response body, got:\n%s", body)
	}
}

func TestRecordAgentToolCall(t *testing.T) {
	m := &AlertMetrics{Prom: NewPrometheusMetrics()}
	m.RecordAgentToolCall("k8s", "kubectl_exec", "ok", 250*time.Millisecond)
	m.RecordAgentToolCall("k8s", "kubectl_exec", "rejected_verb", 1*time.Millisecond)

	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	m.MetricsHandler()(rr, req)
	body := rr.Body.String()

	if !strings.Contains(body, `agent_tool_calls_total{outcome="ok",source="k8s",tool="kubectl_exec"} 1`) {
		t.Errorf("missing ok counter line; body:\n%s", body)
	}
	if !strings.Contains(body, `agent_tool_calls_total{outcome="rejected_verb",source="k8s",tool="kubectl_exec"} 1`) {
		t.Errorf("missing rejected_verb counter line; body:\n%s", body)
	}
	if !strings.Contains(body, `agent_tool_duration_seconds_bucket{source="k8s",tool="kubectl_exec",le=`) {
		t.Errorf("missing duration histogram; body:\n%s", body)
	}
}

func TestRecordAgentRounds(t *testing.T) {
	m := &AlertMetrics{Prom: NewPrometheusMetrics()}
	m.RecordAgentRounds("k8s", 3, false)
	m.RecordAgentRounds("k8s", 10, true)

	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	m.MetricsHandler()(rr, req)
	body := rr.Body.String()

	if !strings.Contains(body, `agent_rounds_used_count{source="k8s"} 2`) {
		t.Errorf("missing rounds_used count; body:\n%s", body)
	}
	if !strings.Contains(body, `agent_rounds_exhausted_total{source="k8s"} 1`) {
		t.Errorf("missing exhausted counter; body:\n%s", body)
	}
}

func TestRecordClaudeUsage_IncrementsAllCounters(t *testing.T) {
	prom := NewPrometheusMetrics()
	m := &AlertMetrics{Prom: prom}

	m.RecordClaudeUsage("k8s", "warning", "claude-haiku-4-5", 100, 50, 200, 300)

	gather := func(name string) float64 {
		mfs, _ := prom.Registry().Gather()
		for _, mf := range mfs {
			if mf.GetName() == name {
				for _, m := range mf.GetMetric() {
					return m.GetCounter().GetValue()
				}
			}
		}
		return -1
	}
	if v := gather("claude_input_tokens_total"); v != 100 {
		t.Errorf("input_tokens: got %v, want 100", v)
	}
	if v := gather("claude_output_tokens_total"); v != 50 {
		t.Errorf("output_tokens: got %v", v)
	}
	if v := gather("claude_cache_creation_tokens_total"); v != 200 {
		t.Errorf("cache_creation: got %v", v)
	}
	if v := gather("claude_cache_read_tokens_total"); v != 300 {
		t.Errorf("cache_read: got %v", v)
	}
}

func TestRecordClaudeUsage_NoOpWithNilProm(t *testing.T) {
	m := &AlertMetrics{}
	// Must not panic
	m.RecordClaudeUsage("k8s", "warning", "model", 1, 2, 3, 4)
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
