package k8s

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func makeConfig() Config {
	return Config{
		WebhookSecret:   "test-secret",
		CooldownSeconds: 5,
		SkipResolved:    true,
	}
}

func makeWebhook(alerts []Alert) AlertmanagerWebhook {
	return AlertmanagerWebhook{
		Version: "4",
		Alerts:  alerts,
	}
}

func makeAlert(fingerprint, alertname, status string) Alert {
	return Alert{
		Fingerprint: fingerprint,
		Status:      status,
		Labels:      map[string]string{"alertname": alertname, "severity": "warning"},
		Annotations: map[string]string{"summary": "test alert"},
		StartsAt:    time.Now(),
	}
}

func postWebhook(t *testing.T, handler http.HandlerFunc, authToken string, payload any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req := httptest.NewRequest("POST", "/webhook", bytes.NewReader(body))
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}
	rr := httptest.NewRecorder()
	handler(rr, req)
	return rr
}

func TestHandleWebhook_UnauthorizedMissingToken(t *testing.T) {
	cfg := makeConfig()
	cd := shared.NewCooldownManager()
	var enqueued atomic.Int32
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	req := httptest.NewRequest("POST", "/webhook", bytes.NewReader([]byte(`{}`)))
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
	if enqueued.Load() != 0 {
		t.Error("no alerts should be enqueued for unauthorized request")
	}
}

func TestHandleWebhook_UnauthorizedWrongToken(t *testing.T) {
	cfg := makeConfig()
	cd := shared.NewCooldownManager()
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool { return true }, nil, nil, shared.NewNopHistoryStore())

	rr := postWebhook(t, handler, "wrong-secret", makeWebhook(nil))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// TestHandleWebhook_AuthRejectionIsLengthIndependent asserts the auth-failure
// response is identical regardless of the Authorization header length, so a
// remote caller cannot probe the secret length through response divergence.
// Regression guard: a previous implementation passed the raw header bytes to
// subtle.ConstantTimeCompare, which short-circuits on length mismatch.
func TestHandleWebhook_AuthRejectionIsLengthIndependent(t *testing.T) {
	cfg := makeConfig()
	cd := shared.NewCooldownManager()
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool { return true }, nil, nil, shared.NewNopHistoryStore())

	// Cover lengths shorter, equal, and longer than the real expected token
	// ("Bearer test-secret" = 18 bytes), plus an empty header.
	wrongHeaders := []string{
		"",
		"x",
		"Bearer x",
		"Bearer wrong-tokn",                 // 1 byte shorter than secret
		"Bearer wrong-token",                // exact length, wrong content
		"Bearer wrong-token-suffix",         // longer
		strings.Repeat("a", 1024),           // far longer
		"Basic " + strings.Repeat("Z", 200), // different scheme, much longer
	}

	var firstBody string
	for i, h := range wrongHeaders {
		req := httptest.NewRequest("POST", "/webhook", bytes.NewReader([]byte(`{}`)))
		if h != "" {
			req.Header.Set("Authorization", h)
		}
		rr := httptest.NewRecorder()
		handler(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("header %q: expected 401, got %d", h, rr.Code)
		}
		if i == 0 {
			firstBody = rr.Body.String()
			continue
		}
		if got := rr.Body.String(); got != firstBody {
			t.Errorf("header %q: body %q differs from baseline %q (length leak through response)", h, got, firstBody)
		}
	}
}

func TestHandleWebhook_InvalidJSON(t *testing.T) {
	cfg := makeConfig()
	cd := shared.NewCooldownManager()
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool { return true }, nil, nil, shared.NewNopHistoryStore())

	req := httptest.NewRequest("POST", "/webhook", bytes.NewReader([]byte(`not json`)))
	req.Header.Set("Authorization", "Bearer test-secret")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// TestHandleWebhook_InvalidJSON_NoInternalDetails verifies that JSON parse errors
// do not leak internal error messages (offset, field names, etc.) to the caller.
func TestHandleWebhook_InvalidJSON_NoInternalDetails(t *testing.T) {
	cfg := makeConfig()
	cd := shared.NewCooldownManager()
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool { return true }, nil, nil, shared.NewNopHistoryStore())

	req := httptest.NewRequest("POST", "/webhook", bytes.NewReader([]byte(`{"alerts": [1, 2, `)))
	req.Header.Set("Authorization", "Bearer test-secret")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
	body := rr.Body.String()
	for _, leak := range []string{"offset", "unexpected end", "json:", "syntax error"} {
		if strings.Contains(strings.ToLower(body), leak) {
			t.Errorf("response body leaks internal JSON error detail %q: %s", leak, body)
		}
	}
}

func TestHandleWebhook_EmptyAlerts(t *testing.T) {
	cfg := makeConfig()
	cd := shared.NewCooldownManager()
	var enqueued atomic.Int32
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	rr := postWebhook(t, handler, "test-secret", makeWebhook([]Alert{}))
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if enqueued.Load() != 0 {
		t.Error("expected no enqueued alerts")
	}
}

func TestHandleWebhook_SkipsResolvedAlerts(t *testing.T) {
	cfg := makeConfig()
	cfg.SkipResolved = true
	cd := shared.NewCooldownManager()
	var enqueued atomic.Int32
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	alerts := []Alert{
		makeAlert("fp1", "TestAlert", "resolved"),
	}
	rr := postWebhook(t, handler, "test-secret", makeWebhook(alerts))
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if enqueued.Load() != 0 {
		t.Errorf("expected 0 enqueued, got %d", enqueued.Load())
	}
}

func TestHandleWebhook_ResolvedClearsCooldown(t *testing.T) {
	cfg := makeConfig()
	cfg.SkipResolved = true
	cfg.CooldownSeconds = 60
	cd := shared.NewCooldownManager()
	var enqueued atomic.Int32
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	// Step 1: fire the alert → enqueued, cooldown set.
	firingAlerts := []Alert{makeAlert("fp-resolved", "TestFlap", "firing")}
	postWebhook(t, handler, "test-secret", makeWebhook(firingAlerts))
	if enqueued.Load() != 1 {
		t.Fatalf("expected 1 enqueued after firing, got %d", enqueued.Load())
	}

	// Step 2: resolve the alert → skipped, but cooldown must be cleared.
	resolvedAlerts := []Alert{makeAlert("fp-resolved", "TestFlap", "resolved")}
	rr := postWebhook(t, handler, "test-secret", makeWebhook(resolvedAlerts))
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for resolved, got %d", rr.Code)
	}
	if enqueued.Load() != 1 {
		t.Errorf("resolved alert should not be enqueued, got %d", enqueued.Load())
	}

	// Step 3: same alert fires again within TTL — must NOT be blocked by cooldown.
	postWebhook(t, handler, "test-secret", makeWebhook(firingAlerts))
	if enqueued.Load() != 2 {
		t.Errorf("expected 2 enqueued after re-fire (cooldown should have been cleared by resolution), got %d", enqueued.Load())
	}
}

func TestHandleWebhook_ResolvedClearsGroupCooldown(t *testing.T) {
	cfg := makeConfig()
	cfg.SkipResolved = true
	cfg.CooldownSeconds = 60
	cfg.GroupCooldownTTL = time.Minute
	cd := shared.NewCooldownManager()
	var enqueued atomic.Int32
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	// Step 1: fire alert with fingerprint fp-a, sets both FP and group cooldowns.
	alertA := Alert{Fingerprint: "fp-a", Labels: map[string]string{"alertname": "PodCrashLooping", "namespace": "prod", "severity": "warning"}, Status: "firing"}
	postWebhook(t, handler, "test-secret", makeWebhook([]Alert{alertA}))
	if enqueued.Load() != 1 {
		t.Fatalf("step 1: expected 1 enqueued, got %d", enqueued.Load())
	}

	// Step 2: resolve alert fp-a → must clear BOTH fingerprint and group cooldowns.
	alertAResolved := Alert{Fingerprint: "fp-a", Labels: alertA.Labels, Status: "resolved"}
	postWebhook(t, handler, "test-secret", makeWebhook([]Alert{alertAResolved}))
	if enqueued.Load() != 1 {
		t.Fatalf("step 2: resolved should not enqueue, got %d", enqueued.Load())
	}

	// Step 3: new alert with DIFFERENT fingerprint but SAME alertname+namespace (same group key).
	// Before the fix, the group cooldown was not cleared on resolution, so this would be
	// silently suppressed even though the original alert resolved.
	alertB := Alert{Fingerprint: "fp-b", Labels: alertA.Labels, Status: "firing"}
	postWebhook(t, handler, "test-secret", makeWebhook([]Alert{alertB}))
	if enqueued.Load() != 2 {
		t.Errorf("step 3: expected 2 enqueued after group-cooldown cleared by resolution, got %d (group cooldown not cleared by resolved alert)", enqueued.Load())
	}
}

func TestHandleWebhook_EnqueuesFiringAlert(t *testing.T) {
	cfg := makeConfig()
	cd := shared.NewCooldownManager()
	var enqueued atomic.Int32
	var receivedAlert shared.AlertPayload
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		receivedAlert = ap
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	alerts := []Alert{
		makeAlert("fp-firing", "TestFiring", "firing"),
	}
	rr := postWebhook(t, handler, "test-secret", makeWebhook(alerts))
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if enqueued.Load() != 1 {
		t.Errorf("expected 1 enqueued, got %d", enqueued.Load())
	}
	if receivedAlert.Fingerprint != "fp-firing" {
		t.Errorf("unexpected fingerprint: %s", receivedAlert.Fingerprint)
	}
	if receivedAlert.Source != "k8s" {
		t.Errorf("expected source k8s, got %s", receivedAlert.Source)
	}
	if receivedAlert.Fields["label:alertname"] != "TestFiring" {
		t.Errorf("expected label:alertname=TestFiring, got %s", receivedAlert.Fields["label:alertname"])
	}
	if receivedAlert.Fields["annotation:summary"] != "test alert" {
		t.Errorf("expected annotation:summary, got %s", receivedAlert.Fields["annotation:summary"])
	}
	if receivedAlert.Fields["status"] != "firing" {
		t.Errorf("expected status=firing, got %s", receivedAlert.Fields["status"])
	}
}

func TestHandleWebhook_CooldownDeduplicates(t *testing.T) {
	cfg := makeConfig()
	cfg.CooldownSeconds = 60
	cd := shared.NewCooldownManager()
	var enqueued atomic.Int32
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	alerts := []Alert{makeAlert("fp-dedup", "TestDedup", "firing")}

	// First request: should enqueue
	postWebhook(t, handler, "test-secret", makeWebhook(alerts))
	if enqueued.Load() != 1 {
		t.Fatalf("expected 1 after first request, got %d", enqueued.Load())
	}

	// Second request with same fingerprint: should be blocked by cooldown
	postWebhook(t, handler, "test-secret", makeWebhook(alerts))
	if enqueued.Load() != 1 {
		t.Errorf("expected still 1 after second request (cooldown), got %d", enqueued.Load())
	}
}

func TestHandleWebhook_CooldownIncrementsMetric(t *testing.T) {
	cfg := makeConfig()
	cfg.CooldownSeconds = 60
	cd := shared.NewCooldownManager()
	metrics := shared.NewAlertMetrics(shared.NewPrometheusMetricsForTest(shared.ProductK8s))
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		return true
	}, metrics, nil, shared.NewNopHistoryStore())

	alerts := []Alert{makeAlert("fp-metric", "TestMetric", "firing")}

	postWebhook(t, handler, "test-secret", makeWebhook(alerts))
	if int64(testutil.ToFloat64(metrics.Prom.AlertsDropped.WithLabelValues("cooldown"))) != 0 {
		t.Errorf("expected 0 cooldown skips after first request, got %d", int64(testutil.ToFloat64(metrics.Prom.AlertsDropped.WithLabelValues("cooldown"))))
	}

	postWebhook(t, handler, "test-secret", makeWebhook(alerts))
	if int64(testutil.ToFloat64(metrics.Prom.AlertsDropped.WithLabelValues("cooldown"))) != 1 {
		t.Errorf("expected 1 cooldown skip after duplicate request, got %d", int64(testutil.ToFloat64(metrics.Prom.AlertsDropped.WithLabelValues("cooldown"))))
	}
}

// TestHandleWebhook_CooldownIncrementsPrometheusCounter verifies that when an
// alert is blocked by the cooldown the labeled Prometheus counter
// alerts_cooldown_total{source="k8s"} is incremented via RecordCooldown.
// The existing TestHandleWebhook_CooldownIncrementsMetric uses
// shared.NewAlertMetrics(shared.NewPrometheusMetricsForTest(shared.ProductK8s)) (Prom == nil) so RecordCooldown is a no-op there;
// this test exercises the non-nil path so that a mutation removing the
// RecordCooldown call in the handler would be detected.
func TestHandleWebhook_CooldownIncrementsPrometheusCounter(t *testing.T) {
	cfg := makeConfig()
	cfg.CooldownSeconds = 60
	cd := shared.NewCooldownManager()
	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetricsForTest(shared.ProductK8s)}
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool { return true }, metrics, nil, shared.NewNopHistoryStore())

	alerts := []Alert{makeAlert("fp-prom-cd", "TestPrometheus", "firing")}
	// First request: accepted, cooldown set — RecordCooldown not called yet.
	postWebhook(t, handler, "test-secret", makeWebhook(alerts))
	// Second request: blocked by cooldown → RecordCooldown must be called.
	postWebhook(t, handler, "test-secret", makeWebhook(alerts))

	got := testutil.ToFloat64(metrics.Prom.AlertsDropped.WithLabelValues("cooldown"))
	if got != 1 {
		t.Errorf("alerts_cooldown_total{source=\"k8s\"} = %v, want 1", got)
	}
}

func TestHandleWebhook_QueueFull_Returns503(t *testing.T) {
	cfg := makeConfig()
	cd := shared.NewCooldownManager()
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		return false // queue always full
	}, nil, nil, shared.NewNopHistoryStore())

	alerts := []Alert{makeAlert("fp-full", "TestFull", "firing")}
	rr := postWebhook(t, handler, "test-secret", makeWebhook(alerts))
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

func TestHandleWebhook_QueueFull_ClearsCooldown(t *testing.T) {
	cfg := makeConfig()
	cfg.CooldownSeconds = 60
	cd := shared.NewCooldownManager()
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		return false // queue always full
	}, nil, nil, shared.NewNopHistoryStore())

	alerts := []Alert{makeAlert("fp-clear", "TestClear", "firing")}
	postWebhook(t, handler, "test-secret", makeWebhook(alerts))

	// After queue-full, cooldown should be cleared so next request can retry
	var enqueued atomic.Int32
	handler2 := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		return true
	}, nil, nil, shared.NewNopHistoryStore())
	postWebhook(t, handler2, "test-secret", makeWebhook(alerts))
	if enqueued.Load() != 1 {
		t.Errorf("expected alert re-enqueued after cooldown cleared, got %d", enqueued.Load())
	}
}

func TestHandleWebhook_MultipleAlerts_PartialEnqueue(t *testing.T) {
	cfg := makeConfig()
	cd := shared.NewCooldownManager()
	var enqueued atomic.Int32
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		// Accept fp1 only
		if ap.Fingerprint == "fp-multi-1" {
			enqueued.Add(1)
			return true
		}
		return false // queue full for fp2
	}, nil, nil, shared.NewNopHistoryStore())

	alerts := []Alert{
		makeAlert("fp-multi-1", "Alert1", "firing"),
		makeAlert("fp-multi-2", "Alert2", "firing"),
	}
	rr := postWebhook(t, handler, "test-secret", makeWebhook(alerts))
	// Any dropped alert should cause 503
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for partial drop, got %d", rr.Code)
	}
	if enqueued.Load() != 1 {
		t.Errorf("expected 1 enqueued, got %d", enqueued.Load())
	}
}

func TestHandleWebhook_ResolvedNotSkipped_WhenDisabled(t *testing.T) {
	cfg := makeConfig()
	cfg.SkipResolved = false
	cd := shared.NewCooldownManager()
	var enqueued atomic.Int32
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	alerts := []Alert{makeAlert("fp-res", "TestResolved", "resolved")}
	postWebhook(t, handler, "test-secret", makeWebhook(alerts))
	if enqueued.Load() != 1 {
		t.Errorf("expected resolved alert enqueued when SkipResolved=false, got %d", enqueued.Load())
	}
}

func TestHandleWebhook_AlertFieldsPopulated(t *testing.T) {
	cfg := makeConfig()
	cd := shared.NewCooldownManager()
	var received shared.AlertPayload
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		received = ap
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	alert := Alert{
		Fingerprint: "fp-fields",
		Status:      "firing",
		Labels:      map[string]string{"alertname": "HighCPU", "severity": "critical", "namespace": "production"},
		Annotations: map[string]string{"description": "CPU is high", "runbook": "http://wiki/runbook"},
		StartsAt:    time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC),
	}
	postWebhook(t, handler, "test-secret", makeWebhook([]Alert{alert}))

	if received.Title != "HighCPU" {
		t.Errorf("expected title HighCPU, got %q", received.Title)
	}
	if received.Severity != "critical" {
		t.Errorf("expected severity critical, got %q", received.Severity)
	}
	if received.Fields["label:namespace"] != "production" {
		t.Errorf("expected namespace label, got %q", received.Fields["label:namespace"])
	}
	if received.Fields["annotation:runbook"] != "http://wiki/runbook" {
		t.Errorf("expected runbook annotation, got %q", received.Fields["annotation:runbook"])
	}
	startsAt := received.Fields["startsAt"]
	if startsAt == "" {
		t.Error("expected startsAt field")
	}
}

func TestHandleWebhook_BodyTooLarge_Returns413(t *testing.T) {
	cfg := makeConfig()
	cd := shared.NewCooldownManager()
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool { return true }, nil, nil, shared.NewNopHistoryStore())

	// Build a body slightly larger than the 1 MiB limit.
	oversized := make([]byte, maxWebhookBodyBytes+1)
	for i := range oversized {
		oversized[i] = 'x'
	}
	req := httptest.NewRequest("POST", "/webhook", bytes.NewReader(oversized))
	req.Header.Set("Authorization", "Bearer test-secret")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413, got %d", rr.Code)
	}
}

// TestHandleWebhook_ExactBodySizeAccepted verifies the exact boundary of the
// MaxBytesReader cap in HandleWebhook: a body of exactly maxWebhookBodyBytes must
// be read in full and not trigger the 413 guard. Paired with
// TestHandleWebhook_BodyTooLarge_Returns413 (maxWebhookBodyBytes+1 → 413), this
// closes the mutation gap where the limit could silently shift by one byte.
func TestHandleWebhook_ExactBodySizeAccepted(t *testing.T) {
	cfg := makeConfig()
	cd := shared.NewCooldownManager()
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool { return true }, nil, nil, shared.NewNopHistoryStore())

	// Build a valid (empty-alerts) Alertmanager JSON payload padded with trailing
	// spaces to exactly maxWebhookBodyBytes bytes. json.Unmarshal accepts trailing
	// whitespace, so the test exercises the MaxBytesReader cap rather than JSON parsing.
	base := `{"version":"4","groupKey":"","status":"firing","receiver":"r","groupLabels":{},"commonLabels":{},"commonAnnotations":{},"externalURL":"","alerts":[]}`
	body := base + strings.Repeat(" ", maxWebhookBodyBytes-len(base))
	if len(body) != maxWebhookBodyBytes {
		t.Fatalf("body length %d != maxWebhookBodyBytes %d", len(body), maxWebhookBodyBytes)
	}

	req := httptest.NewRequest("POST", "/webhook", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-secret")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code == http.StatusRequestEntityTooLarge {
		t.Errorf("body at exactly maxWebhookBodyBytes should not be rejected with 413")
	}
}

func TestPromqlQuery_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `{
			"status": "success",
			"data": {
				"resultType": "vector",
				"result": [
					{"metric": {"job": "node"}, "value": [1700000000, "0.42"]}
				]
			}
		}`)
	}))
	defer srv.Close()

	prom := &PrometheusClient{HTTP: srv.Client(), URL: srv.URL}
	result := prom.queryForPrompt(context.Background(), `up`)
	if result == "" {
		t.Error("expected non-empty result")
	}
	if result == "(no data)" || result == "(failed to parse response)" {
		t.Errorf("unexpected result: %s", result)
	}
}

func TestPromqlQuery_NoData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
	}))
	defer srv.Close()

	prom := &PrometheusClient{HTTP: srv.Client(), URL: srv.URL}
	result := prom.queryForPrompt(context.Background(), `up`)
	if result != "(no data)" {
		t.Errorf("expected (no data), got %q", result)
	}
}

func TestPromqlQuery_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "error")
	}))
	defer srv.Close()

	// The query function returns early for non-200 status codes, reporting the
	// HTTP status without attempting to parse the body.
	prom := &PrometheusClient{HTTP: srv.Client(), URL: srv.URL}
	result := prom.queryForPrompt(context.Background(), `up`)
	if result == "" {
		t.Error("expected non-empty error result")
	}
	if !strings.Contains(result, "500") {
		t.Errorf("expected HTTP status code 500 in result, got %q", result)
	}
}

func TestPromqlQuery_Unreachable(t *testing.T) {
	prom := &PrometheusClient{HTTP: &http.Client{Timeout: time.Second}, URL: "http://127.0.0.1:1"}
	result := prom.queryForPrompt(context.Background(), `up`)
	if result == "" {
		t.Error("expected non-empty error result for unreachable server")
	}
}

// TestHandleWebhook_TooManyAlerts verifies that a batch exceeding maxAlertsPerBatch
// is rejected with 413 before any alerts are processed.
func TestHandleWebhook_TooManyAlerts(t *testing.T) {
	cfg := makeConfig()
	cd := shared.NewCooldownManager()
	var enqueued atomic.Int32
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	alerts := make([]Alert, maxAlertsPerBatch+1)
	for i := range alerts {
		alerts[i] = makeAlert(fmt.Sprintf("fp-%d", i), "TestAlert", "firing")
	}
	rr := postWebhook(t, handler, "test-secret", makeWebhook(alerts))

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413 for oversized batch, got %d", rr.Code)
	}
	if enqueued.Load() != 0 {
		t.Errorf("expected no alerts enqueued, got %d", enqueued.Load())
	}
}

// TestHandleWebhook_ExactMaxAlerts verifies that a batch of exactly maxAlertsPerBatch
// alerts is accepted.
func TestHandleWebhook_ExactMaxAlerts(t *testing.T) {
	cfg := makeConfig()
	cd := shared.NewCooldownManager()
	var enqueued atomic.Int32
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	alerts := make([]Alert, maxAlertsPerBatch)
	for i := range alerts {
		alerts[i] = makeAlert(fmt.Sprintf("fp-exact-%d", i), "TestAlert", "firing")
	}
	rr := postWebhook(t, handler, "test-secret", makeWebhook(alerts))

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for batch of exactly %d alerts, got %d", maxAlertsPerBatch, rr.Code)
	}
	if int(enqueued.Load()) != maxAlertsPerBatch {
		t.Errorf("expected %d enqueued, got %d", maxAlertsPerBatch, enqueued.Load())
	}
}

// TestHandleWebhook_EmptyFingerprintSkipped verifies that an alert with an empty
// fingerprint is silently skipped. An empty fingerprint must not be used as a
// cooldown key because all fingerprint-less alerts would collide into one slot,
// causing the second and subsequent alerts to be silently suppressed.
func TestHandleWebhook_EmptyFingerprintSkipped(t *testing.T) {
	cfg := makeConfig()
	cd := shared.NewCooldownManager()
	var enqueued atomic.Int32
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	alerts := []Alert{
		{
			Fingerprint: "",
			Status:      "firing",
			Labels:      map[string]string{"alertname": "NoFingerprint", "severity": "warning"},
			Annotations: map[string]string{},
			StartsAt:    time.Now(),
		},
	}
	rr := postWebhook(t, handler, "test-secret", makeWebhook(alerts))

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 (alert silently skipped), got %d", rr.Code)
	}
	if enqueued.Load() != 0 {
		t.Errorf("expected 0 enqueued for empty fingerprint, got %d", enqueued.Load())
	}
}

// TestHandleWebhook_OversizedFingerprintSkipped verifies that an alert with a
// fingerprint exceeding maxFingerprintLen is silently skipped rather than
// inserted into the cooldown map with an unbounded key.
func TestHandleWebhook_OversizedFingerprintSkipped(t *testing.T) {
	cfg := makeConfig()
	cd := shared.NewCooldownManager()
	var enqueued atomic.Int32
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	oversizedFP := strings.Repeat("a", maxFingerprintLen+1)
	alerts := []Alert{
		{
			Fingerprint: oversizedFP,
			Status:      "firing",
			Labels:      map[string]string{"alertname": "OversizedFP", "severity": "warning"},
			Annotations: map[string]string{},
			StartsAt:    time.Now(),
		},
	}
	rr := postWebhook(t, handler, "test-secret", makeWebhook(alerts))

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 (alert silently skipped), got %d", rr.Code)
	}
	if enqueued.Load() != 0 {
		t.Errorf("expected 0 enqueued for oversized fingerprint, got %d", enqueued.Load())
	}
}

// TestHandleWebhook_ExactMaxFingerprintAccepted verifies the exact boundary of
// the fingerprint-length guard: an alert whose fingerprint is exactly
// maxFingerprintLen bytes must be accepted and enqueued. Paired with
// TestHandleWebhook_OversizedFingerprintSkipped (len > maxFingerprintLen →
// skipped), this closes the mutation gap where `>` could become `>=` in the
// guard `len(alert.Fingerprint) > maxFingerprintLen`, which would silently drop
// valid 256-byte fingerprints and cause alerts to disappear without any metric.
func TestHandleWebhook_ExactMaxFingerprintAccepted(t *testing.T) {
	cfg := makeConfig()
	cd := shared.NewCooldownManager()
	var enqueued atomic.Int32
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	exactFP := strings.Repeat("a", maxFingerprintLen)
	alerts := []Alert{
		{
			Fingerprint: exactFP,
			Status:      "firing",
			Labels:      map[string]string{"alertname": "ExactFP", "severity": "warning"},
			Annotations: map[string]string{},
			StartsAt:    time.Now(),
		},
	}
	rr := postWebhook(t, handler, "test-secret", makeWebhook(alerts))

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for exact-length fingerprint, got %d", rr.Code)
	}
	if enqueued.Load() != 1 {
		t.Errorf("expected 1 enqueued for exact-length fingerprint, got %d", enqueued.Load())
	}
}

// TestHandler_PopulatesSeverityLevel verifies that AlertPayload.SeverityLevel
// is populated from the alert labels via SeverityFromAlertmanager.
func TestHandler_PopulatesSeverityLevel(t *testing.T) {
	cfg := makeConfig()
	cd := shared.NewCooldownManager()
	var captured shared.AlertPayload
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		captured = ap
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	alert := Alert{
		Fingerprint: "fp-severity",
		Status:      "firing",
		Labels:      map[string]string{"alertname": "CriticalAlert", "severity": "critical"},
		Annotations: map[string]string{},
		StartsAt:    time.Now(),
	}
	rr := postWebhook(t, handler, "test-secret", makeWebhook([]Alert{alert}))
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if captured.SeverityLevel != shared.SeverityCritical {
		t.Errorf("expected SeverityCritical, got %v", captured.SeverityLevel)
	}
}

// TestHandler_PopulatesSeverityLevel_Warning verifies that an Alertmanager
// alert with severity label "warning" maps to SeverityWarning in
// AlertPayload.SeverityLevel. "warning" is the most common production label
// for threshold alerts (disk fill, CPU throttle, memory pressure); if
// SeverityFromAlertmanager returned the wrong Severity, all warning-severity
// k8s alerts would silently use the wrong model and tool-loop budget via
// policy.ModelFor / policy.MaxRoundsFor. The existing test covers only the
// "critical" path, leaving the warning path — the most common case —
// completely untested for the routing field.
func TestHandler_PopulatesSeverityLevel_Warning(t *testing.T) {
	cfg := makeConfig()
	cd := shared.NewCooldownManager()
	var captured shared.AlertPayload
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		captured = ap
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	alert := Alert{
		Fingerprint: "fp-warning",
		Status:      "firing",
		Labels:      map[string]string{"alertname": "DiskAlmostFull", "severity": "warning"},
		Annotations: map[string]string{},
		StartsAt:    time.Now(),
	}
	rr := postWebhook(t, handler, "test-secret", makeWebhook([]Alert{alert}))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if captured.SeverityLevel != shared.SeverityWarning {
		t.Errorf("expected SeverityWarning, got %v", captured.SeverityLevel)
	}
}

// TestHandler_PopulatesSeverityLevel_Info verifies that an Alertmanager alert
// with severity label "info" maps to SeverityInfo in AlertPayload.SeverityLevel.
// SeverityInfo is distinct from SeverityWarning and lets operators configure
// MAX_AGENT_ROUNDS_INFO=0 to skip agentic analysis for low-priority informational
// alerts, reducing costs. A regression returning SeverityWarning for "info" labels
// would silently trigger full tool-loop analysis on every info-level alert without
// any config-time error.
func TestHandler_PopulatesSeverityLevel_Info(t *testing.T) {
	cfg := makeConfig()
	cd := shared.NewCooldownManager()
	var captured shared.AlertPayload
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		captured = ap
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	alert := Alert{
		Fingerprint: "fp-info",
		Status:      "firing",
		Labels:      map[string]string{"alertname": "InfoAlert", "severity": "info"},
		Annotations: map[string]string{},
		StartsAt:    time.Now(),
	}
	rr := postWebhook(t, handler, "test-secret", makeWebhook([]Alert{alert}))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if captured.SeverityLevel != shared.SeverityInfo {
		t.Errorf("expected SeverityInfo, got %v", captured.SeverityLevel)
	}
}

// TestHandler_PopulatesSeverityLevel_Page verifies that an Alertmanager alert
// with severity label "page" maps to SeverityCritical in
// AlertPayload.SeverityLevel. "page" is a real-world severity label used by
// PagerDuty-integrated Alertmanager setups as an alias for "critical"; it is
// listed alongside "critical" in SeverityFromAlertmanager's switch arm.
// Operators may configure CLAUDE_MODEL_CRITICAL and MAX_AGENT_ROUNDS_CRITICAL
// overrides; if "page" silently mapped to SeverityWarning instead, those
// operator configs would be bypassed for every page-severity alert.
func TestHandler_PopulatesSeverityLevel_Page(t *testing.T) {
	cfg := makeConfig()
	cd := shared.NewCooldownManager()
	var captured shared.AlertPayload
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		captured = ap
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	alert := Alert{
		Fingerprint: "fp-page",
		Status:      "firing",
		Labels:      map[string]string{"alertname": "PageAlert", "severity": "page"},
		Annotations: map[string]string{},
		StartsAt:    time.Now(),
	}
	rr := postWebhook(t, handler, "test-secret", makeWebhook([]Alert{alert}))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if captured.SeverityLevel != shared.SeverityCritical {
		t.Errorf("expected SeverityCritical for 'page' label, got %v", captured.SeverityLevel)
	}
}

// TestHandler_PopulatesSeverityLevel_Notice verifies that an Alertmanager alert
// with severity label "notice" maps to SeverityWarning in
// AlertPayload.SeverityLevel. "notice" is a low-urgency warning label used by
// some alerting systems and is listed alongside "warning" in
// SeverityFromAlertmanager's switch arm. It is covered at the unit-test level
// in severity_test.go but was not exercised through the full handler path.
func TestHandler_PopulatesSeverityLevel_Notice(t *testing.T) {
	cfg := makeConfig()
	cd := shared.NewCooldownManager()
	var captured shared.AlertPayload
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		captured = ap
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	alert := Alert{
		Fingerprint: "fp-notice",
		Status:      "firing",
		Labels:      map[string]string{"alertname": "NoticeAlert", "severity": "notice"},
		Annotations: map[string]string{},
		StartsAt:    time.Now(),
	}
	rr := postWebhook(t, handler, "test-secret", makeWebhook([]Alert{alert}))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if captured.SeverityLevel != shared.SeverityWarning {
		t.Errorf("expected SeverityWarning for 'notice' label, got %v", captured.SeverityLevel)
	}
}

// TestHandler_PopulatesSeverityLevel_UnknownDefaultsToWarning verifies that an
// Alertmanager alert with an unrecognized severity label defaults to
// SeverityWarning in AlertPayload.SeverityLevel. The defensive default in
// SeverityFromAlertmanager ensures that any alert with a non-standard severity
// label (e.g. "severe", "fatal", or a typo) still triggers a full analysis
// rather than being silently downgraded. If this path incorrectly returned
// SeverityInfo or SeverityUnknown, an operator's MAX_AGENT_ROUNDS_WARNING
// config would be bypassed for all such alerts.
func TestHandler_PopulatesSeverityLevel_UnknownDefaultsToWarning(t *testing.T) {
	cfg := makeConfig()
	cd := shared.NewCooldownManager()
	var captured shared.AlertPayload
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		captured = ap
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	alert := Alert{
		Fingerprint: "fp-unknown-sev",
		Status:      "firing",
		Labels:      map[string]string{"alertname": "UnknownSevAlert", "severity": "severe"},
		Annotations: map[string]string{},
		StartsAt:    time.Now(),
	}
	rr := postWebhook(t, handler, "test-secret", makeWebhook([]Alert{alert}))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if captured.SeverityLevel != shared.SeverityWarning {
		t.Errorf("expected SeverityWarning for unknown severity label, got %v", captured.SeverityLevel)
	}
}

// TestHandleWebhook_InvalidFingerprintIncrementsMetric verifies that alerts
// dropped for an empty or oversized fingerprint increment the
// AlertsInvalidFingerprint counter so operators can detect malformed payloads
// via Prometheus alerting rules.
func TestHandleWebhook_InvalidFingerprintIncrementsMetric(t *testing.T) {
	cfg := makeConfig()
	cd := shared.NewCooldownManager()
	metrics := shared.NewAlertMetrics(shared.NewPrometheusMetricsForTest(shared.ProductK8s))
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool { return true }, metrics, nil, shared.NewNopHistoryStore())

	// One alert with empty fingerprint, one with oversized fingerprint.
	oversizedFP := strings.Repeat("x", maxFingerprintLen+1)
	alerts := []Alert{
		{Fingerprint: "", Status: "firing", Labels: map[string]string{"alertname": "EmptyFP"}, Annotations: map[string]string{}, StartsAt: time.Now()},
		{Fingerprint: oversizedFP, Status: "firing", Labels: map[string]string{"alertname": "OversizedFP"}, Annotations: map[string]string{}, StartsAt: time.Now()},
	}
	rr := postWebhook(t, handler, "test-secret", makeWebhook(alerts))

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if int64(testutil.ToFloat64(metrics.Prom.AlertsDropped.WithLabelValues("invalid_fingerprint"))) != 2 {
		t.Errorf("expected AlertsInvalidFingerprint=2, got %d", int64(testutil.ToFloat64(metrics.Prom.AlertsDropped.WithLabelValues("invalid_fingerprint"))))
	}
}

func TestHandleWebhook_GroupCooldownDeduplicates(t *testing.T) {
	cm := shared.NewCooldownManager()
	enqueued := 0
	enqueue := func(shared.AlertPayload) bool { enqueued++; return true }
	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetricsForTest(shared.ProductK8s)}

	cfg := Config{WebhookSecret: "s", CooldownSeconds: 60, GroupCooldownTTL: time.Minute}
	h := HandleWebhook(cfg, cm, enqueue, metrics, nil, shared.NewNopHistoryStore()) // nil StormDetector

	body1 := `{"alerts":[{"fingerprint":"fp1","labels":{"alertname":"PodCrashLooping","namespace":"prod","severity":"warning"}}]}`
	req := httptest.NewRequest("POST", "/webhook", strings.NewReader(body1))
	req.Header.Set("Authorization", "Bearer s")
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != 200 || enqueued != 1 {
		t.Fatalf("first call: code=%d enqueued=%d", rec.Code, enqueued)
	}

	// Second alert: DIFFERENT fingerprint, SAME group key (alertname:namespace)
	body2 := `{"alerts":[{"fingerprint":"fp2","labels":{"alertname":"PodCrashLooping","namespace":"prod","severity":"warning"}}]}`
	req = httptest.NewRequest("POST", "/webhook", strings.NewReader(body2))
	req.Header.Set("Authorization", "Bearer s")
	rec = httptest.NewRecorder()
	h(rec, req)
	if enqueued != 1 {
		t.Fatalf("group-deduped second call should not enqueue; got enqueued=%d", enqueued)
	}
	if int64(testutil.ToFloat64(metrics.Prom.AlertsDropped.WithLabelValues("group_cooldown"))) != 1 {
		t.Fatalf("AlertsDropped[group_cooldown]=%d, want 1", int64(testutil.ToFloat64(metrics.Prom.AlertsDropped.WithLabelValues("group_cooldown"))))
	}
}

func TestHandleWebhook_GroupKeyEmptyNamespaceFallback(t *testing.T) {
	cm := shared.NewCooldownManager()
	enqueued := 0
	enqueue := func(shared.AlertPayload) bool { enqueued++; return true }
	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetricsForTest(shared.ProductK8s)}
	cfg := Config{WebhookSecret: "s", CooldownSeconds: 60, GroupCooldownTTL: time.Minute}
	h := HandleWebhook(cfg, cm, enqueue, metrics, nil, shared.NewNopHistoryStore())

	// Two alerts with same alertname, no namespace — both should map to alertname:_cluster_ group
	bodies := []string{
		`{"alerts":[{"fingerprint":"a","labels":{"alertname":"KubeAPIDown","severity":"critical"}}]}`,
		`{"alerts":[{"fingerprint":"b","labels":{"alertname":"KubeAPIDown","severity":"critical"}}]}`,
	}
	for _, body := range bodies {
		req := httptest.NewRequest("POST", "/webhook", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer s")
		h(httptest.NewRecorder(), req)
	}
	if enqueued != 1 {
		t.Fatalf("empty-namespace deduplication: enqueued=%d, want 1 (second deduped via _cluster_)", enqueued)
	}
}

func TestHandleWebhook_StormRecordIncrementsAfterCooldownCheck(t *testing.T) {
	cm := shared.NewCooldownManager()
	enqueue := func(shared.AlertPayload) bool { return true }
	storm := shared.NewStormDetector(1000, time.Now)
	cfg := Config{WebhookSecret: "s", CooldownSeconds: 60}
	h := HandleWebhook(cfg, cm, enqueue, &shared.AlertMetrics{}, storm, shared.NewNopHistoryStore())

	// Three distinct fingerprints — all should pass cooldown and be recorded
	for i := 1; i <= 3; i++ {
		body := fmt.Sprintf(`{"alerts":[{"fingerprint":"f%d","labels":{"alertname":"X","namespace":"ns","severity":"warning"}}]}`, i)
		req := httptest.NewRequest("POST", "/webhook", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer s")
		h(httptest.NewRecorder(), req)
	}
	if got := storm.Count(); got != 3 {
		t.Fatalf("storm.Count()=%d, want 3", got)
	}

	// Same fingerprint as alert 1 → cooldown hit → NOT recorded by storm
	body := `{"alerts":[{"fingerprint":"f1","labels":{"alertname":"X","namespace":"ns","severity":"warning"}}]}`
	req := httptest.NewRequest("POST", "/webhook", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer s")
	h(httptest.NewRecorder(), req)
	if got := storm.Count(); got != 3 {
		t.Fatalf("after cooldown-dedup, storm.Count()=%d, want still 3", got)
	}
}

type fakeHistory struct{ fires int }

func (f *fakeHistory) RecordFire(context.Context, string, shared.Severity)             { f.fires++ }
func (f *fakeHistory) RecordAnalysis(context.Context, string, shared.Severity, string) {}
func (f *fakeHistory) Lookup(context.Context, string) shared.HistoryView               { return shared.HistoryView{} }
func (f *fakeHistory) Close() error                                                    { return nil }

func TestHandlerRecordsFireBeforeCooldown(t *testing.T) {
	hist := &fakeHistory{}
	cfg := Config{WebhookSecret: "s", CooldownSeconds: 300}
	cd := shared.NewCooldownManager()
	enqueue := func(shared.AlertPayload) bool { return true }
	h := HandleWebhook(cfg, cd, enqueue, shared.NewAlertMetrics(nil), nil, hist)

	body := `{"alerts":[{"fingerprint":"fp-aaa","status":"firing","labels":{"alertname":"X","severity":"warning"}}]}`
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer s")
		w := httptest.NewRecorder()
		h(w, req)
	}
	if hist.fires != 2 {
		t.Errorf("RecordFire called %d times, want 2", hist.fires)
	}
}

func TestGroupKeyFromLabels(t *testing.T) {
	cases := []struct {
		name   string
		labels map[string]string
		want   string
	}{
		{
			name:   "namespace present",
			labels: map[string]string{"alertname": "PodCrashLooping", "namespace": "prod"},
			want:   "15:PodCrashLooping4:prod",
		},
		{
			name:   "empty namespace uses _cluster_ sentinel",
			labels: map[string]string{"alertname": "KubeAPIDown", "namespace": ""},
			want:   "11:KubeAPIDown9:_cluster_",
		},
		{
			name:   "missing namespace key uses _cluster_ sentinel",
			labels: map[string]string{"alertname": "KubeAPIDown"},
			want:   "11:KubeAPIDown9:_cluster_",
		},
		{
			name:   "empty alertname",
			labels: map[string]string{"alertname": "", "namespace": "staging"},
			want:   "0:7:staging",
		},
		{
			// Length prefixes prevent collision when alertname or namespace
			// contains ":" — otherwise these two inputs would both produce
			// "Foo:bar:baz" under the old plain-join scheme.
			name:   "colon in alertname does not collide with colon in namespace",
			labels: map[string]string{"alertname": "Foo:bar", "namespace": "baz"},
			want:   "7:Foo:bar3:baz",
		},
		{
			name:   "colon-prefixed namespace",
			labels: map[string]string{"alertname": "Foo", "namespace": "bar:baz"},
			want:   "3:Foo7:bar:baz",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := groupKeyFromLabels(tc.labels)
			if got != tc.want {
				t.Errorf("groupKeyFromLabels(%v) = %q, want %q", tc.labels, got, tc.want)
			}
		})
	}
}

// TestHandleWebhook_OversizedAlertDropped verifies that an alert whose
// aggregate label+annotation byte size (after per-value truncation) exceeds
// maxAlertFieldsBytes is skipped with an oversized_alert drop metric, while
// the remaining alerts in the same batch are still queued. Guards the
// cost/abuse vector from issue #34: a label-flood alert must not reach the
// work queue or the Claude prompt.
func TestHandleWebhook_OversizedAlertDropped(t *testing.T) {
	cfg := makeConfig()
	cd := shared.NewCooldownManager()
	metrics := shared.NewAlertMetrics(shared.NewPrometheusMetricsForTest(shared.ProductK8s))
	var captured []shared.AlertPayload
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		captured = append(captured, ap)
		return true
	}, metrics, nil, shared.NewNopHistoryStore())

	// Five 4 KiB annotation values are each within the per-value cap, but sum
	// to ~20 KiB aggregate — over the 16 KiB per-alert cap.
	oversizedAnnotations := make(map[string]string)
	for i := 0; i < 5; i++ {
		oversizedAnnotations[fmt.Sprintf("junk%d", i)] = strings.Repeat("x", maxFieldValueBytes)
	}
	alerts := []Alert{
		{Fingerprint: "fp-oversized", Status: "firing", Labels: map[string]string{"alertname": "Oversized"}, Annotations: oversizedAnnotations, StartsAt: time.Now()},
		{Fingerprint: "fp-normal", Status: "firing", Labels: map[string]string{"alertname": "Normal"}, Annotations: map[string]string{}, StartsAt: time.Now()},
	}
	rr := postWebhook(t, handler, "test-secret", makeWebhook(alerts))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if len(captured) != 1 || captured[0].Fingerprint != "fp-normal" {
		t.Errorf("expected only fp-normal queued, got %d payloads", len(captured))
	}
	if got := int64(testutil.ToFloat64(metrics.Prom.AlertsDropped.WithLabelValues("oversized_alert"))); got != 1 {
		t.Errorf("expected oversized_alert drops=1, got %d", got)
	}
}

// TestHandleWebhook_TruncatesLongFieldValues verifies that a single long
// annotation value (e.g. a verbose description) is truncated with a marker
// rather than causing the whole alert to be rejected — long single
// annotations are legitimate, only their unbounded size is not.
func TestHandleWebhook_TruncatesLongFieldValues(t *testing.T) {
	cfg := makeConfig()
	cd := shared.NewCooldownManager()
	var captured shared.AlertPayload
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		captured = ap
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	alert := Alert{
		Fingerprint: "fp-long-desc",
		Status:      "firing",
		Labels:      map[string]string{"alertname": "LongDesc"},
		Annotations: map[string]string{"description": strings.Repeat("d", 2*maxFieldValueBytes)},
		StartsAt:    time.Now(),
	}
	rr := postWebhook(t, handler, "test-secret", makeWebhook([]Alert{alert}))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if captured.Fingerprint != "fp-long-desc" {
		t.Fatal("expected alert with one long annotation to be queued, not dropped")
	}
	desc := captured.Fields["annotation:description"]
	if len(desc) > maxFieldValueBytes {
		t.Errorf("expected annotation:description truncated to <= %d bytes, got %d", maxFieldValueBytes, len(desc))
	}
	if !strings.HasSuffix(desc, "[truncated]") {
		t.Errorf("expected truncation marker suffix, got tail %q", desc[max(0, len(desc)-32):])
	}
}
