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
	}, nil)

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
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool { return true }, nil)

	rr := postWebhook(t, handler, "wrong-secret", makeWebhook(nil))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestHandleWebhook_InvalidJSON(t *testing.T) {
	cfg := makeConfig()
	cd := shared.NewCooldownManager()
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool { return true }, nil)

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
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool { return true }, nil)

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
	}, nil)

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
	}, nil)

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
	}, nil)

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

func TestHandleWebhook_EnqueuesFiringAlert(t *testing.T) {
	cfg := makeConfig()
	cd := shared.NewCooldownManager()
	var enqueued atomic.Int32
	var receivedAlert shared.AlertPayload
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		receivedAlert = ap
		return true
	}, nil)

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
	}, nil)

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
	metrics := new(shared.AlertMetrics)
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		return true
	}, metrics)

	alerts := []Alert{makeAlert("fp-metric", "TestMetric", "firing")}

	postWebhook(t, handler, "test-secret", makeWebhook(alerts))
	if metrics.AlertsCooldown.Load() != 0 {
		t.Errorf("expected 0 cooldown skips after first request, got %d", metrics.AlertsCooldown.Load())
	}

	postWebhook(t, handler, "test-secret", makeWebhook(alerts))
	if metrics.AlertsCooldown.Load() != 1 {
		t.Errorf("expected 1 cooldown skip after duplicate request, got %d", metrics.AlertsCooldown.Load())
	}
}

// TestHandleWebhook_CooldownIncrementsPrometheusCounter verifies that when an
// alert is blocked by the cooldown the labeled Prometheus counter
// alerts_cooldown_total{source="k8s"} is incremented via RecordCooldown.
// The existing TestHandleWebhook_CooldownIncrementsMetric uses
// new(shared.AlertMetrics) (Prom == nil) so RecordCooldown is a no-op there;
// this test exercises the non-nil path so that a mutation removing the
// RecordCooldown call in the handler would be detected.
func TestHandleWebhook_CooldownIncrementsPrometheusCounter(t *testing.T) {
	cfg := makeConfig()
	cfg.CooldownSeconds = 60
	cd := shared.NewCooldownManager()
	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetrics()}
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool { return true }, metrics)

	alerts := []Alert{makeAlert("fp-prom-cd", "TestPrometheus", "firing")}
	// First request: accepted, cooldown set — RecordCooldown not called yet.
	postWebhook(t, handler, "test-secret", makeWebhook(alerts))
	// Second request: blocked by cooldown → RecordCooldown must be called.
	postWebhook(t, handler, "test-secret", makeWebhook(alerts))

	got := testutil.ToFloat64(metrics.Prom.AlertsCooldown.WithLabelValues("k8s"))
	if got != 1 {
		t.Errorf("alerts_cooldown_total{source=\"k8s\"} = %v, want 1", got)
	}
}

func TestHandleWebhook_QueueFull_Returns503(t *testing.T) {
	cfg := makeConfig()
	cd := shared.NewCooldownManager()
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		return false // queue always full
	}, nil)

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
	}, nil)

	alerts := []Alert{makeAlert("fp-clear", "TestClear", "firing")}
	postWebhook(t, handler, "test-secret", makeWebhook(alerts))

	// After queue-full, cooldown should be cleared so next request can retry
	var enqueued atomic.Int32
	handler2 := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		return true
	}, nil)
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
	}, nil)

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
	}, nil)

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
	}, nil)

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
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool { return true }, nil)

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
	result := prom.query(context.Background(), `up`)
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
	result := prom.query(context.Background(), `up`)
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
	result := prom.query(context.Background(), `up`)
	if result == "" {
		t.Error("expected non-empty error result")
	}
	if !strings.Contains(result, "500") {
		t.Errorf("expected HTTP status code 500 in result, got %q", result)
	}
}

func TestPromqlQuery_Unreachable(t *testing.T) {
	prom := &PrometheusClient{HTTP: &http.Client{Timeout: time.Second}, URL: "http://127.0.0.1:1"}
	result := prom.query(context.Background(), `up`)
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
	}, nil)

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
	}, nil)

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
	}, nil)

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
	}, nil)

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

// TestHandleWebhook_InvalidFingerprintIncrementsMetric verifies that alerts
// dropped for an empty or oversized fingerprint increment the
// AlertsInvalidFingerprint counter so operators can detect malformed payloads
// via Prometheus alerting rules.
func TestHandleWebhook_InvalidFingerprintIncrementsMetric(t *testing.T) {
	cfg := makeConfig()
	cd := shared.NewCooldownManager()
	metrics := new(shared.AlertMetrics)
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool { return true }, metrics)

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
	if metrics.AlertsInvalidFingerprint.Load() != 2 {
		t.Errorf("expected AlertsInvalidFingerprint=2, got %d", metrics.AlertsInvalidFingerprint.Load())
	}
}
