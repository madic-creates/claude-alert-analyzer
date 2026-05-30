package checkmk

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

func makeCheckmkConfig() Config {
	return Config{
		WebhookSecret:   "test-secret",
		CooldownSeconds: 5,
	}
}

func postCheckmkWebhook(t *testing.T, handler http.HandlerFunc, authToken string, payload any) *httptest.ResponseRecorder {
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

func makeNotification(hostname, service, state, notifType string) CheckMKNotification {
	return CheckMKNotification{
		Hostname:           hostname,
		HostAddress:        "10.0.0.1",
		ServiceDescription: service,
		ServiceState:       state,
		ServiceOutput:      "Check output",
		NotificationType:   notifType,
		PerfData:           "",
		Timestamp:          "2024-01-15T12:00:00Z",
	}
}

func TestCheckmkHandleWebhook_UnauthorizedMissingToken(t *testing.T) {
	cfg := makeCheckmkConfig()
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

func TestCheckmkHandleWebhook_UnauthorizedWrongToken(t *testing.T) {
	cfg := makeCheckmkConfig()
	cd := shared.NewCooldownManager()
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool { return true }, nil, nil, shared.NewNopHistoryStore())

	notif := makeNotification("host1", "CPU", "WARNING", "PROBLEM")
	rr := postCheckmkWebhook(t, handler, "wrong-secret", notif)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// TestCheckmkHandleWebhook_AuthRejectionIsLengthIndependent asserts the
// auth-failure response is identical regardless of the Authorization header
// length, so a remote caller cannot probe the secret length through response
// divergence. Regression guard: a previous implementation passed the raw
// header bytes to subtle.ConstantTimeCompare, which short-circuits on length
// mismatch.
func TestCheckmkHandleWebhook_AuthRejectionIsLengthIndependent(t *testing.T) {
	cfg := makeCheckmkConfig()
	cd := shared.NewCooldownManager()
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool { return true }, nil, nil, shared.NewNopHistoryStore())

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

func TestCheckmkHandleWebhook_InvalidJSON(t *testing.T) {
	cfg := makeCheckmkConfig()
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

// TestCheckmkHandleWebhook_InvalidJSON_NoInternalDetails verifies that JSON
// parse errors do not leak internal error details (e.g. offset, field names)
// to the caller. Returning raw Go error messages exposes implementation details
// and can aid an attacker in crafting malicious payloads.
func TestCheckmkHandleWebhook_InvalidJSON_NoInternalDetails(t *testing.T) {
	cfg := makeCheckmkConfig()
	cd := shared.NewCooldownManager()
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool { return true }, nil, nil, shared.NewNopHistoryStore())

	req := httptest.NewRequest("POST", "/webhook", bytes.NewReader([]byte(`{"bad": [1, 2, `)))
	req.Header.Set("Authorization", "Bearer test-secret")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
	body := rr.Body.String()
	// Must not contain Go-internal terms that reveal implementation details.
	for _, leak := range []string{"offset", "unexpected end", "json:", "syntax error"} {
		if strings.Contains(strings.ToLower(body), leak) {
			t.Errorf("response body leaks internal JSON error detail %q: %s", leak, body)
		}
	}
}

func TestCheckmkHandleWebhook_SkipsRecovery(t *testing.T) {
	cfg := makeCheckmkConfig()
	cd := shared.NewCooldownManager()
	var enqueued atomic.Int32
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	notif := makeNotification("host1", "CPU", "OK", "RECOVERY")
	rr := postCheckmkWebhook(t, handler, "test-secret", notif)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if enqueued.Load() != 0 {
		t.Errorf("expected 0 enqueued for recovery, got %d", enqueued.Load())
	}
}

// TestCheckmkHandleWebhook_RecoveryClearsCooldown verifies that when a RECOVERY
// notification arrives it clears the cooldown for the corresponding PROBLEM so
// that a service which fails again within the TTL window is not silently suppressed.
func TestCheckmkHandleWebhook_RecoveryClearsCooldown(t *testing.T) {
	cfg := makeCheckmkConfig()
	cfg.CooldownSeconds = 60 // long TTL so the test is deterministic
	cd := shared.NewCooldownManager()
	var enqueued atomic.Int32
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	// First PROBLEM: should be enqueued and set cooldown.
	problem := makeNotification("host1", "CPU", "CRITICAL", "PROBLEM")
	postCheckmkWebhook(t, handler, "test-secret", problem)
	if enqueued.Load() != 1 {
		t.Fatalf("expected 1 enqueued after first PROBLEM, got %d", enqueued.Load())
	}

	// RECOVERY: should be skipped but must clear the PROBLEM cooldown.
	recovery := makeNotification("host1", "CPU", "OK", "RECOVERY")
	postCheckmkWebhook(t, handler, "test-secret", recovery)
	if enqueued.Load() != 1 {
		t.Errorf("RECOVERY should not be enqueued, still expect 1, got %d", enqueued.Load())
	}

	// Second PROBLEM (same host+service) within original TTL window: should be
	// enqueued because the RECOVERY cleared the cooldown.
	postCheckmkWebhook(t, handler, "test-secret", problem)
	if enqueued.Load() != 2 {
		t.Errorf("expected 2 enqueued after second PROBLEM (cooldown cleared by RECOVERY), got %d", enqueued.Load())
	}
}

// TestCheckmkHandleWebhook_RecoveryClearsFlapCooldown verifies that a RECOVERY
// notification also clears cooldown entries for FLAPPING START and FLAPPING STOP
// notification types. Without this fix, a service that starts flapping (generating
// a FLAPPING START alert) and then recovers would remain in cooldown for the full
// TTL, causing the next flap event to be silently suppressed.
func TestCheckmkHandleWebhook_RecoveryClearsFlapCooldown(t *testing.T) {
	cfg := makeCheckmkConfig()
	cfg.CooldownSeconds = 60 // long TTL so cooldown is still active on second attempt
	cd := shared.NewCooldownManager()
	var enqueued atomic.Int32
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	// FLAPPING START: should be enqueued and set a cooldown keyed on "FLAPPINGSTART".
	flap := makeNotification("host1", "Disk", "WARNING", "FLAPPINGSTART")
	postCheckmkWebhook(t, handler, "test-secret", flap)
	if enqueued.Load() != 1 {
		t.Fatalf("expected 1 enqueued after FLAPPING START, got %d", enqueued.Load())
	}

	// RECOVERY: must clear the FLAPPING START cooldown in addition to PROBLEM cooldowns.
	recovery := makeNotification("host1", "Disk", "OK", "RECOVERY")
	postCheckmkWebhook(t, handler, "test-secret", recovery)
	if enqueued.Load() != 1 {
		t.Errorf("RECOVERY should not be enqueued, still expect 1, got %d", enqueued.Load())
	}

	// Second FLAPPING START within original TTL window: must be enqueued because the
	// RECOVERY cleared the FLAPPING START cooldown.
	postCheckmkWebhook(t, handler, "test-secret", flap)
	if enqueued.Load() != 2 {
		t.Errorf("expected 2 enqueued after second FLAPPING START (cooldown cleared by RECOVERY), got %d", enqueued.Load())
	}
}

// TestCheckmkHandleWebhook_RecoveryClearsGroupCooldown verifies that a RECOVERY
// notification clears the group-level cooldown so a subsequent alert with a
// different fingerprint but the same hostname:service group key can be processed
// within the original TTL window — the checkmk analogue of k8s
// TestHandleWebhook_ResolvedClearsGroupCooldown.
func TestCheckmkHandleWebhook_RecoveryClearsGroupCooldown(t *testing.T) {
	cfg := makeCheckmkConfig()
	cfg.CooldownSeconds = 60
	cfg.GroupCooldownTTL = time.Minute
	cd := shared.NewCooldownManager()
	var enqueued atomic.Int32
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	// Step 1: fire alert A (PROBLEM:CRITICAL) → sets both FP and group cooldowns.
	alertA := makeNotification("host1", "CPU", "CRITICAL", "PROBLEM")
	postCheckmkWebhook(t, handler, "test-secret", alertA)
	if enqueued.Load() != 1 {
		t.Fatalf("step 1: expected 1 enqueued, got %d", enqueued.Load())
	}

	// Step 2: alert B has a different fingerprint (FLAPPINGSTART:WARNING) but the
	// same group key (host1:CPU). Within the TTL it must be blocked by group cooldown.
	alertB := makeNotification("host1", "CPU", "WARNING", "FLAPPINGSTART")
	postCheckmkWebhook(t, handler, "test-secret", alertB)
	if enqueued.Load() != 1 {
		t.Fatalf("step 2: expected group cooldown to block alert B, got %d enqueued", enqueued.Load())
	}

	// Step 3: RECOVERY for host1:CPU clears all FP cooldowns AND the group cooldown.
	// The RECOVERY notification itself must not be enqueued.
	recovery := makeNotification("host1", "CPU", "OK", "RECOVERY")
	postCheckmkWebhook(t, handler, "test-secret", recovery)
	if enqueued.Load() != 1 {
		t.Errorf("step 3: RECOVERY should not be enqueued, still expect 1, got %d", enqueued.Load())
	}

	// Step 4: alert B again (different FP from A, same group key) must now be enqueued
	// because RECOVERY cleared the group cooldown.
	postCheckmkWebhook(t, handler, "test-secret", alertB)
	if enqueued.Load() != 2 {
		t.Errorf("step 4: expected 2 enqueued after group-cooldown cleared by RECOVERY, got %d", enqueued.Load())
	}
}

func TestCheckmkHandleWebhook_EnqueuesProblem(t *testing.T) {
	cfg := makeCheckmkConfig()
	cd := shared.NewCooldownManager()
	var received shared.AlertPayload
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		received = ap
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	notif := makeNotification("webserver01", "HTTP", "CRITICAL", "PROBLEM")
	rr := postCheckmkWebhook(t, handler, "test-secret", notif)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if received.Source != "checkmk" {
		t.Errorf("expected source checkmk, got %q", received.Source)
	}
	if received.Fields["hostname"] != "webserver01" {
		t.Errorf("expected hostname webserver01, got %q", received.Fields["hostname"])
	}
	if received.Fields["service_description"] != "HTTP" {
		t.Errorf("expected service_description HTTP, got %q", received.Fields["service_description"])
	}
	if received.Fields["service_state"] != "CRITICAL" {
		t.Errorf("expected service_state CRITICAL, got %q", received.Fields["service_state"])
	}
	if received.Fields["notification_type"] != "PROBLEM" {
		t.Errorf("expected notification_type PROBLEM, got %q", received.Fields["notification_type"])
	}
	if received.Severity != "critical" {
		t.Errorf("expected severity critical, got %q", received.Severity)
	}
}

func TestCheckmkHandleWebhook_SeverityMapping(t *testing.T) {
	cases := []struct {
		state    string
		expected string
	}{
		{"CRITICAL", "critical"},
		{"WARNING", "warning"},
		{"UNKNOWN", "unknown"},
		{"OK", "ok"},
	}

	for _, tc := range cases {
		t.Run(tc.state, func(t *testing.T) {
			cfg := makeCheckmkConfig()
			cd := shared.NewCooldownManager()
			var received shared.AlertPayload
			handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
				received = ap
				return true
			}, nil, nil, shared.NewNopHistoryStore())
			notif := makeNotification("host1", "SVC", tc.state, "PROBLEM")
			postCheckmkWebhook(t, handler, "test-secret", notif)
			if received.Severity != tc.expected {
				t.Errorf("state %s: expected severity %q, got %q", tc.state, tc.expected, received.Severity)
			}
		})
	}
}

func TestCheckmkHandleWebhook_CooldownDeduplicates(t *testing.T) {
	cfg := makeCheckmkConfig()
	cfg.CooldownSeconds = 60
	cd := shared.NewCooldownManager()
	var enqueued atomic.Int32
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	notif := makeNotification("host1", "CPU", "WARNING", "PROBLEM")

	// First request: should enqueue
	postCheckmkWebhook(t, handler, "test-secret", notif)
	if enqueued.Load() != 1 {
		t.Fatalf("expected 1 after first request, got %d", enqueued.Load())
	}

	// Second request with same fingerprint: should be blocked by cooldown
	postCheckmkWebhook(t, handler, "test-secret", notif)
	if enqueued.Load() != 1 {
		t.Errorf("expected still 1 after second request (cooldown), got %d", enqueued.Load())
	}
}

func TestCheckmkHandleWebhook_CooldownIncrementsMetric(t *testing.T) {
	cfg := makeCheckmkConfig()
	cfg.CooldownSeconds = 60
	cd := shared.NewCooldownManager()
	metrics := shared.NewAlertMetrics(shared.NewPrometheusMetricsForTest(shared.ProductCheckMK))
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		return true
	}, metrics, nil, shared.NewNopHistoryStore())

	notif := makeNotification("host1", "CPU", "WARNING", "PROBLEM")

	postCheckmkWebhook(t, handler, "test-secret", notif)
	if int64(testutil.ToFloat64(metrics.Prom.AlertsDropped.WithLabelValues("cooldown"))) != 0 {
		t.Errorf("expected 0 cooldown skips after first request, got %d", int64(testutil.ToFloat64(metrics.Prom.AlertsDropped.WithLabelValues("cooldown"))))
	}

	postCheckmkWebhook(t, handler, "test-secret", notif)
	if int64(testutil.ToFloat64(metrics.Prom.AlertsDropped.WithLabelValues("cooldown"))) != 1 {
		t.Errorf("expected 1 cooldown skip after duplicate request, got %d", int64(testutil.ToFloat64(metrics.Prom.AlertsDropped.WithLabelValues("cooldown"))))
	}
}

// TestCheckmkHandleWebhook_CooldownIncrementsPrometheusCounter verifies that when
// an alert is blocked by the cooldown the labeled Prometheus counter
// alerts_cooldown_total{source="checkmk"} is incremented via RecordCooldown.
// The existing TestCheckmkHandleWebhook_CooldownIncrementsMetric uses
// shared.NewAlertMetrics(shared.NewPrometheusMetricsForTest(shared.ProductCheckMK)) (Prom == nil) so RecordCooldown is a no-op there;
// this test exercises the non-nil path so that a mutation removing the
// RecordCooldown call or using the wrong source label would be detected.
func TestCheckmkHandleWebhook_CooldownIncrementsPrometheusCounter(t *testing.T) {
	cfg := makeCheckmkConfig()
	cfg.CooldownSeconds = 60
	cd := shared.NewCooldownManager()
	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetricsForTest(shared.ProductCheckMK)}
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool { return true }, metrics, nil, shared.NewNopHistoryStore())

	notif := makeNotification("host1", "CPU", "WARNING", "PROBLEM")
	// First request: accepted, cooldown set — RecordCooldown not called yet.
	postCheckmkWebhook(t, handler, "test-secret", notif)
	// Second request: blocked by cooldown → RecordCooldown must be called.
	postCheckmkWebhook(t, handler, "test-secret", notif)

	got := testutil.ToFloat64(metrics.Prom.AlertsDropped.WithLabelValues("cooldown"))
	if got != 1 {
		t.Errorf("alerts_cooldown_total{source=\"checkmk\"} = %v, want 1", got)
	}
}

func TestCheckmkHandleWebhook_QueueFull_Returns503(t *testing.T) {
	cfg := makeCheckmkConfig()
	cd := shared.NewCooldownManager()
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		return false // queue always full
	}, nil, nil, shared.NewNopHistoryStore())

	notif := makeNotification("host1", "CPU", "WARNING", "PROBLEM")
	rr := postCheckmkWebhook(t, handler, "test-secret", notif)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

func TestCheckmkHandleWebhook_QueueFull_ClearsCooldown(t *testing.T) {
	cfg := makeCheckmkConfig()
	cfg.CooldownSeconds = 60
	cd := shared.NewCooldownManager()

	// First attempt: queue full
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		return false
	}, nil, nil, shared.NewNopHistoryStore())
	notif := makeNotification("host1", "Disk", "CRITICAL", "PROBLEM")
	postCheckmkWebhook(t, handler, "test-secret", notif)

	// Second attempt with working queue: should succeed (cooldown cleared)
	var enqueued atomic.Int32
	handler2 := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		return true
	}, nil, nil, shared.NewNopHistoryStore())
	postCheckmkWebhook(t, handler2, "test-secret", notif)
	if enqueued.Load() != 1 {
		t.Errorf("expected alert re-enqueued after cooldown cleared, got %d", enqueued.Load())
	}
}

func TestCheckmkHandleWebhook_AllFieldsPopulated(t *testing.T) {
	cfg := makeCheckmkConfig()
	cd := shared.NewCooldownManager()
	var received shared.AlertPayload
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		received = ap
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	notif := CheckMKNotification{
		Hostname:           "db01",
		HostAddress:        "192.168.1.10",
		ServiceDescription: "MySQL",
		ServiceState:       "CRITICAL",
		ServiceOutput:      "Connection refused",
		HostState:          "UP",
		NotificationType:   "PROBLEM",
		PerfData:           "connections=0",
		LongPluginOutput:   "Extended output here",
		Timestamp:          "2024-01-15T12:00:00Z",
	}
	rr := postCheckmkWebhook(t, handler, "test-secret", notif)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	expectedFields := map[string]string{
		"hostname":            "db01",
		"host_address":        "192.168.1.10",
		"service_description": "MySQL",
		"service_state":       "CRITICAL",
		"service_output":      "Connection refused",
		"host_state":          "UP",
		"notification_type":   "PROBLEM",
		"perf_data":           "connections=0",
		"long_plugin_output":  "Extended output here",
		"timestamp":           "2024-01-15T12:00:00Z",
	}
	for field, expected := range expectedFields {
		if got := received.Fields[field]; got != expected {
			t.Errorf("field %q: expected %q, got %q", field, expected, got)
		}
	}
	if received.Title != "db01 - MySQL" {
		t.Errorf("expected title 'db01 - MySQL', got %q", received.Title)
	}
}

func TestCheckmkHandleWebhook_FingerprintNotEmpty(t *testing.T) {
	cfg := makeCheckmkConfig()
	cd := shared.NewCooldownManager()
	var received shared.AlertPayload
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		received = ap
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	notif := makeNotification("host1", "CPU", "WARNING", "PROBLEM")
	postCheckmkWebhook(t, handler, "test-secret", notif)
	if received.Fingerprint == "" {
		t.Error("expected non-empty fingerprint")
	}
}

func TestCheckmkHandleWebhook_BodyTooLarge_Returns413(t *testing.T) {
	cfg := makeCheckmkConfig()
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

func TestCheckmkHandleWebhook_HostDown_SeverityCritical(t *testing.T) {
	// Host-level notification: ServiceState is empty, HostState is "DOWN".
	// Must produce severity "critical", not the default "warning".
	cfg := makeCheckmkConfig()
	cd := shared.NewCooldownManager()
	var got shared.AlertPayload
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		got = ap
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	notif := CheckMKNotification{
		Hostname:         "myhost",
		HostAddress:      "10.0.0.2",
		HostState:        "DOWN",
		ServiceState:     "",
		NotificationType: "PROBLEM",
		Timestamp:        "2024-01-15T12:00:00Z",
	}
	rr := postCheckmkWebhook(t, handler, "test-secret", notif)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if got.Severity != "critical" {
		t.Errorf("expected severity 'critical' for host DOWN, got %q", got.Severity)
	}
}

func TestCheckmkHandleWebhook_HostUp_SeverityOK(t *testing.T) {
	// Host-level notification: ServiceState is empty, HostState is "UP".
	// This occurs for ACKNOWLEDGEMENT or DOWNTIME notifications on a host that is
	// currently UP. The handler must produce severity "ok", not the default "warning".
	cfg := makeCheckmkConfig()
	cd := shared.NewCooldownManager()
	var got shared.AlertPayload
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		got = ap
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	notif := CheckMKNotification{
		Hostname:         "myhost",
		HostAddress:      "10.0.0.2",
		HostState:        "UP",
		ServiceState:     "",
		NotificationType: "ACKNOWLEDGEMENT",
		Timestamp:        "2024-01-15T12:00:00Z",
	}
	rr := postCheckmkWebhook(t, handler, "test-secret", notif)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if got.Severity != "ok" {
		t.Errorf("expected severity 'ok' for host UP notification, got %q", got.Severity)
	}
}

func TestCheckmkHandleWebhook_HostUnreachable_SeverityCritical(t *testing.T) {
	cfg := makeCheckmkConfig()
	cd := shared.NewCooldownManager()
	var got shared.AlertPayload
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		got = ap
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	notif := CheckMKNotification{
		Hostname:         "myhost",
		HostAddress:      "10.0.0.2",
		HostState:        "UNREACHABLE",
		ServiceState:     "",
		NotificationType: "PROBLEM",
		Timestamp:        "2024-01-15T12:00:00Z",
	}
	rr := postCheckmkWebhook(t, handler, "test-secret", notif)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if got.Severity != "critical" {
		t.Errorf("expected severity 'critical' for host UNREACHABLE, got %q", got.Severity)
	}
}

func TestCheckmkHandleWebhook_HostDown_TitleIsHostnameOnly(t *testing.T) {
	// Host-level notifications have an empty ServiceDescription.
	// The alert title must be just the hostname, not "hostname - ".
	cfg := makeCheckmkConfig()
	cd := shared.NewCooldownManager()
	var got shared.AlertPayload
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		got = ap
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	notif := CheckMKNotification{
		Hostname:         "myhost",
		HostAddress:      "10.0.0.2",
		HostState:        "DOWN",
		ServiceState:     "",
		NotificationType: "PROBLEM",
		Timestamp:        "2024-01-15T12:00:00Z",
	}
	rr := postCheckmkWebhook(t, handler, "test-secret", notif)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if got.Title != "myhost" {
		t.Errorf("expected title %q for host-level notification, got %q", "myhost", got.Title)
	}
}

func TestCheckmkHandleWebhook_HostRecovery_ClearsCooldown(t *testing.T) {
	// Host-down PROBLEM sets a cooldown with empty ServiceState.
	// A subsequent RECOVERY must clear that cooldown so the next PROBLEM is analyzed.
	cfg := makeCheckmkConfig()
	cd := shared.NewCooldownManager()
	var enqueued atomic.Int32
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	hostDownNotif := CheckMKNotification{
		Hostname: "myhost", HostAddress: "10.0.0.2",
		HostState: "DOWN", ServiceState: "", NotificationType: "PROBLEM",
		Timestamp: "2024-01-15T12:00:00Z",
	}
	recoveryNotif := CheckMKNotification{
		Hostname: "myhost", HostAddress: "10.0.0.2",
		HostState: "UP", ServiceState: "", NotificationType: "RECOVERY",
		Timestamp: "2024-01-15T12:01:00Z",
	}

	// First PROBLEM — enqueued.
	postCheckmkWebhook(t, handler, "test-secret", hostDownNotif)
	if enqueued.Load() != 1 {
		t.Fatalf("expected 1 enqueued after first PROBLEM, got %d", enqueued.Load())
	}

	// RECOVERY — clears cooldown, not enqueued.
	postCheckmkWebhook(t, handler, "test-secret", recoveryNotif)
	if enqueued.Load() != 1 {
		t.Fatalf("expected still 1 enqueued after RECOVERY, got %d", enqueued.Load())
	}

	// Second PROBLEM — cooldown cleared, must be enqueued.
	postCheckmkWebhook(t, handler, "test-secret", hostDownNotif)
	if enqueued.Load() != 2 {
		t.Errorf("expected 2 enqueued after second PROBLEM (cooldown cleared by RECOVERY), got %d", enqueued.Load())
	}
}

func TestFingerprint_DifferentInputsProduceDifferentHashes(t *testing.T) {
	fp1 := fingerprint("host1", "CPU", "PROBLEM", "WARNING")
	fp2 := fingerprint("host1", "Disk", "PROBLEM", "WARNING")
	fp3 := fingerprint("host2", "CPU", "PROBLEM", "WARNING")

	if fp1 == fp2 {
		t.Error("different services should produce different fingerprints")
	}
	if fp1 == fp3 {
		t.Error("different hosts should produce different fingerprints")
	}
}

func TestFingerprint_SameInputsProduceSameHash(t *testing.T) {
	fp1 := fingerprint("host1", "CPU", "PROBLEM", "WARNING")
	fp2 := fingerprint("host1", "CPU", "PROBLEM", "WARNING")
	if fp1 != fp2 {
		t.Error("same inputs should produce same fingerprint")
	}
}

func TestFingerprint_Length(t *testing.T) {
	fp := fingerprint("host1", "CPU", "PROBLEM", "WARNING")
	if len(fp) != 64 {
		t.Errorf("expected fingerprint length 64 (full SHA-256 hex), got %d", len(fp))
	}
}

// TestFingerprint_NullByteSeparatorPreventsPrefixCollisions verifies that the
// null-byte separator between parts prevents two differently-split inputs from
// producing the same fingerprint. Without the separator, concatenating the raw
// parts before hashing would make fingerprint("ab","c") == fingerprint("a","bc")
// because both produce the same byte sequence "abc". A collision like that could
// merge cooldowns across distinct alert identifiers (e.g. a host named "host1"
// with service "" vs. host "host" with service "1"), silently suppressing alerts.
// TestCheckmkHandleWebhook_RecoveryClearsAcknowledgementCooldown verifies that a
// RECOVERY notification clears cooldown entries that were set by ACKNOWLEDGEMENT
// notifications. Without this fix, an ACKNOWLEDGEMENT processed during a TTL
// window leaves a stale cooldown entry. When the service later fires a new
// PROBLEM, it would be silently suppressed until the TTL expires — even though
// a RECOVERY was already received.
func TestCheckmkHandleWebhook_RecoveryClearsAcknowledgementCooldown(t *testing.T) {
	cfg := makeCheckmkConfig()
	cfg.CooldownSeconds = 60 // long TTL so cooldown is still active on second attempt
	cd := shared.NewCooldownManager()
	var enqueued atomic.Int32
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	// ACKNOWLEDGEMENT notification: queued and sets a cooldown.
	ack := makeNotification("host1", "Disk", "CRITICAL", "ACKNOWLEDGEMENT")
	postCheckmkWebhook(t, handler, "test-secret", ack)
	if enqueued.Load() != 1 {
		t.Fatalf("expected 1 enqueued after ACKNOWLEDGEMENT, got %d", enqueued.Load())
	}

	// RECOVERY: must clear the ACKNOWLEDGEMENT cooldown.
	recovery := makeNotification("host1", "Disk", "OK", "RECOVERY")
	postCheckmkWebhook(t, handler, "test-secret", recovery)
	if enqueued.Load() != 1 {
		t.Errorf("RECOVERY should not be enqueued, still expect 1, got %d", enqueued.Load())
	}

	// New PROBLEM within original TTL: must be enqueued because RECOVERY cleared
	// the ACKNOWLEDGEMENT cooldown. Without the fix this would be suppressed.
	problem := makeNotification("host1", "Disk", "CRITICAL", "PROBLEM")
	postCheckmkWebhook(t, handler, "test-secret", problem)
	if enqueued.Load() != 2 {
		t.Errorf("expected 2 enqueued after PROBLEM (cooldown cleared by RECOVERY), got %d", enqueued.Load())
	}
}

// TestCheckmkHandleWebhook_RecoveryClearsDowntimeCooldown verifies that a RECOVERY
// notification clears cooldown entries set by DOWNTIME START and DOWNTIME END
// notifications, preventing the next real PROBLEM from being silently suppressed.
func TestCheckmkHandleWebhook_RecoveryClearsDowntimeCooldown(t *testing.T) {
	cfg := makeCheckmkConfig()
	cfg.CooldownSeconds = 60
	cd := shared.NewCooldownManager()
	var enqueued atomic.Int32
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	// DOWNTIME START notification: queued and sets a cooldown.
	downtime := makeNotification("host1", "HTTP", "WARNING", "DOWNTIMESTART")
	postCheckmkWebhook(t, handler, "test-secret", downtime)
	if enqueued.Load() != 1 {
		t.Fatalf("expected 1 enqueued after DOWNTIME START, got %d", enqueued.Load())
	}

	// RECOVERY: must clear the DOWNTIME START cooldown.
	recovery := makeNotification("host1", "HTTP", "OK", "RECOVERY")
	postCheckmkWebhook(t, handler, "test-secret", recovery)
	if enqueued.Load() != 1 {
		t.Errorf("RECOVERY should not be enqueued, still expect 1, got %d", enqueued.Load())
	}

	// New PROBLEM within original TTL: must be enqueued because RECOVERY cleared
	// the DOWNTIME START cooldown. Without the fix this would be suppressed.
	problem := makeNotification("host1", "HTTP", "CRITICAL", "PROBLEM")
	postCheckmkWebhook(t, handler, "test-secret", problem)
	if enqueued.Load() != 2 {
		t.Errorf("expected 2 enqueued after PROBLEM (cooldown cleared by RECOVERY), got %d", enqueued.Load())
	}
}

// TestCheckmkHandleWebhook_RecoveryClearsOKStateCooldown verifies that a RECOVERY
// notification clears cooldown entries whose ServiceState is "OK". This covers the
// case where a non-RECOVERY notification (e.g. DOWNTIME START) arrives for a service
// that is currently in OK state. Without "OK" in the sweep list the fingerprint keyed
// on that state would never be cleared, causing the next PROBLEM to be silently
// suppressed until the TTL expired.
func TestCheckmkHandleWebhook_RecoveryClearsOKStateCooldown(t *testing.T) {
	cfg := makeCheckmkConfig()
	cfg.CooldownSeconds = 60 // long TTL so cooldown is still active on second attempt
	cd := shared.NewCooldownManager()
	var enqueued atomic.Int32
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	// DOWNTIME START on a service that is currently OK: sets a cooldown keyed on "OK".
	downtime := makeNotification("host1", "HTTP", "OK", "DOWNTIMESTART")
	postCheckmkWebhook(t, handler, "test-secret", downtime)
	if enqueued.Load() != 1 {
		t.Fatalf("expected 1 enqueued after DOWNTIME START, got %d", enqueued.Load())
	}

	// RECOVERY: must clear the OK-state DOWNTIME START cooldown.
	recovery := makeNotification("host1", "HTTP", "OK", "RECOVERY")
	postCheckmkWebhook(t, handler, "test-secret", recovery)
	if enqueued.Load() != 1 {
		t.Errorf("RECOVERY should not be enqueued, still expect 1, got %d", enqueued.Load())
	}

	// New PROBLEM within original TTL: must be enqueued because RECOVERY cleared the
	// OK-state cooldown. Without "OK" in the sweep list this would be suppressed.
	problem := makeNotification("host1", "HTTP", "CRITICAL", "PROBLEM")
	postCheckmkWebhook(t, handler, "test-secret", problem)
	if enqueued.Load() != 2 {
		t.Errorf("expected 2 enqueued after PROBLEM (OK-state cooldown cleared by RECOVERY), got %d", enqueued.Load())
	}
}

// TestCheckmkHandleWebhook_RecoveryClearsCustomCooldown verifies that a RECOVERY
// notification clears cooldown entries set by CUSTOM notifications. Without this
// fix a CUSTOM alert that enters cooldown would never be cleared by a RECOVERY,
// causing the next CUSTOM notification within the TTL window to be silently
// suppressed even though the service has already recovered.
func TestCheckmkHandleWebhook_RecoveryClearsCustomCooldown(t *testing.T) {
	cfg := makeCheckmkConfig()
	cfg.CooldownSeconds = 60 // long TTL so cooldown is still active on second attempt
	cd := shared.NewCooldownManager()
	var enqueued atomic.Int32
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	// CUSTOM notification: queued and sets a cooldown keyed on "CUSTOM".
	custom := makeNotification("host1", "Disk", "CRITICAL", "CUSTOM")
	postCheckmkWebhook(t, handler, "test-secret", custom)
	if enqueued.Load() != 1 {
		t.Fatalf("expected 1 enqueued after CUSTOM, got %d", enqueued.Load())
	}

	// RECOVERY: must clear the CUSTOM cooldown.
	recovery := makeNotification("host1", "Disk", "OK", "RECOVERY")
	postCheckmkWebhook(t, handler, "test-secret", recovery)
	if enqueued.Load() != 1 {
		t.Errorf("RECOVERY should not be enqueued, still expect 1, got %d", enqueued.Load())
	}

	// Second CUSTOM within original TTL window: must be enqueued because the
	// RECOVERY cleared the CUSTOM cooldown. Without the fix this would be suppressed.
	postCheckmkWebhook(t, handler, "test-secret", custom)
	if enqueued.Load() != 2 {
		t.Errorf("expected 2 enqueued after second CUSTOM (cooldown cleared by RECOVERY), got %d", enqueued.Load())
	}
}

// TestCheckmkHandleWebhook_RecoveryClearsDowntimeCancelledCooldown verifies that a
// RECOVERY notification clears cooldown entries set by DOWNTIMECANCELLED notifications.
// CheckMK sends DOWNTIMECANCELLED when a scheduled downtime window is cancelled
// before it ends; without clearing this fingerprint, the next real PROBLEM within
// the TTL window would be silently suppressed.
func TestCheckmkHandleWebhook_RecoveryClearsDowntimeCancelledCooldown(t *testing.T) {
	cfg := makeCheckmkConfig()
	cfg.CooldownSeconds = 60
	cd := shared.NewCooldownManager()
	var enqueued atomic.Int32
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	// DOWNTIMECANCELLED notification: queued and sets a cooldown.
	dtCancel := makeNotification("host1", "HTTP", "WARNING", "DOWNTIMECANCELLED")
	postCheckmkWebhook(t, handler, "test-secret", dtCancel)
	if enqueued.Load() != 1 {
		t.Fatalf("expected 1 enqueued after DOWNTIMECANCELLED, got %d", enqueued.Load())
	}

	// RECOVERY: must clear the DOWNTIMECANCELLED cooldown.
	recovery := makeNotification("host1", "HTTP", "OK", "RECOVERY")
	postCheckmkWebhook(t, handler, "test-secret", recovery)
	if enqueued.Load() != 1 {
		t.Errorf("RECOVERY should not be enqueued, still expect 1, got %d", enqueued.Load())
	}

	// New PROBLEM within original TTL: must be enqueued because RECOVERY cleared
	// the DOWNTIMECANCELLED cooldown. Without the fix this would be suppressed.
	problem := makeNotification("host1", "HTTP", "CRITICAL", "PROBLEM")
	postCheckmkWebhook(t, handler, "test-secret", problem)
	if enqueued.Load() != 2 {
		t.Errorf("expected 2 enqueued after PROBLEM (cooldown cleared by RECOVERY), got %d", enqueued.Load())
	}
}

// TestFingerprint_NullByteInPartNoCollision verifies that a null byte embedded
// inside a part value does not collide with the separator between two other parts.
// With the old null-byte-separator scheme, fingerprint("a\x00","b") and
// fingerprint("a","\x00b") both hash the byte sequence a\x00\x00b\x00 because
// the null at the end of "a\x00" merges with the separator null. CheckMK field
// values are operator-supplied strings decoded from JSON (which passes \u0000 as
// a literal null byte), so this collision is reachable in practice. A crafted
// webhook could force two distinct alerts to share a cooldown fingerprint,
// causing one to be silently suppressed.
func TestFingerprint_NullByteInPartNoCollision(t *testing.T) {
	// "a\x00" + "b" vs "a" + "\x00b" — same raw bytes without length prefixes.
	fp1 := fingerprint("a\x00", "b", "", "")
	fp2 := fingerprint("a", "\x00b", "", "")
	if fp1 == fp2 {
		t.Errorf("null byte in part caused fingerprint collision: %s", fp1)
	}
}

func TestHandler_PopulatesSeverityLevel_ServiceCritical(t *testing.T) {
	cfg := makeCheckmkConfig()
	cd := shared.NewCooldownManager()
	var received shared.AlertPayload
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		received = ap
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	notif := makeNotification("host1", "SVC", "CRITICAL", "PROBLEM")
	rr := postCheckmkWebhook(t, handler, "test-secret", notif)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if received.SeverityLevel != shared.SeverityCritical {
		t.Errorf("expected SeverityLevel %v, got %v", shared.SeverityCritical, received.SeverityLevel)
	}
}

func TestHandler_PopulatesSeverityLevel_HostDown(t *testing.T) {
	cfg := makeCheckmkConfig()
	cd := shared.NewCooldownManager()
	var received shared.AlertPayload
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		received = ap
		return true
	}, nil, nil, shared.NewNopHistoryStore())

	notif := CheckMKNotification{
		Hostname:         "myhost",
		HostAddress:      "10.0.0.2",
		HostState:        "DOWN",
		ServiceState:     "",
		NotificationType: "PROBLEM",
		Timestamp:        "2024-01-15T12:00:00Z",
	}
	rr := postCheckmkWebhook(t, handler, "test-secret", notif)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if received.SeverityLevel != shared.SeverityCritical {
		t.Errorf("expected SeverityLevel %v, got %v", shared.SeverityCritical, received.SeverityLevel)
	}
}

func TestFingerprint_NullByteSeparatorPreventsPrefixCollisions(t *testing.T) {
	cases := [][2][4]string{
		// hostname boundary shift: "host1"+"" vs "host"+"1"
		{{"host1", "", "PROBLEM", "CRITICAL"}, {"host", "1", "PROBLEM", "CRITICAL"}},
		// service boundary shift: "CPU"+service vs host+"CPUservice"
		{{"myhost", "CPU", "alert", ""}, {"myhost", "", "CPUalert", ""}},
		// notification type boundary: "PROBLEM"+"CRITICAL" vs "PROBLEMCRITICAL"+""
		{{"h", "s", "PROBLEM", "CRITICAL"}, {"h", "s", "PROBLEMCRITICAL", ""}},
	}
	for _, pair := range cases {
		fp1 := fingerprint(pair[0][0], pair[0][1], pair[0][2], pair[0][3])
		fp2 := fingerprint(pair[1][0], pair[1][1], pair[1][2], pair[1][3])
		if fp1 == fp2 {
			t.Errorf("prefix collision: fingerprint(%q,%q,%q,%q) == fingerprint(%q,%q,%q,%q) = %s",
				pair[0][0], pair[0][1], pair[0][2], pair[0][3],
				pair[1][0], pair[1][1], pair[1][2], pair[1][3], fp1)
		}
	}
}

func TestHandleWebhook_GroupCooldownDeduplicates(t *testing.T) {
	cm := shared.NewCooldownManager()
	enqueued := 0
	enqueue := func(shared.AlertPayload) bool { enqueued++; return true }
	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetricsForTest(shared.ProductCheckMK)}
	cfg := Config{WebhookSecret: "s", CooldownSeconds: 60, GroupCooldownTTL: time.Minute}
	h := HandleWebhook(cfg, cm, enqueue, metrics, nil, shared.NewNopHistoryStore())

	// Two notifications with different states (different fingerprints) but same host+service
	first := `{"hostname":"web01","service_description":"CPU","service_state":"WARNING","notification_type":"PROBLEM"}`
	second := `{"hostname":"web01","service_description":"CPU","service_state":"CRITICAL","notification_type":"PROBLEM"}`
	for _, body := range []string{first, second} {
		req := httptest.NewRequest("POST", "/webhook", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer s")
		h(httptest.NewRecorder(), req)
	}
	if enqueued != 1 {
		t.Fatalf("group-deduped: enqueued=%d, want 1", enqueued)
	}
	if int64(testutil.ToFloat64(metrics.Prom.AlertsDropped.WithLabelValues("group_cooldown"))) != 1 {
		t.Fatalf("AlertsDropped[group_cooldown]=%d, want 1", int64(testutil.ToFloat64(metrics.Prom.AlertsDropped.WithLabelValues("group_cooldown"))))
	}
}

func TestHandleWebhook_GroupKeyEmptyServiceFallback(t *testing.T) {
	cm := shared.NewCooldownManager()
	enqueued := 0
	enqueue := func(shared.AlertPayload) bool { enqueued++; return true }
	cfg := Config{WebhookSecret: "s", CooldownSeconds: 60, GroupCooldownTTL: time.Minute}
	h := HandleWebhook(cfg, cm, enqueue, &shared.AlertMetrics{}, nil, shared.NewNopHistoryStore())

	// Two host-level events (empty service) with different host states — same group key host:_host_
	first := `{"hostname":"db01","service_description":"","host_state":"DOWN","notification_type":"PROBLEM"}`
	second := `{"hostname":"db01","service_description":"","host_state":"UNREACHABLE","notification_type":"PROBLEM"}`
	for _, body := range []string{first, second} {
		req := httptest.NewRequest("POST", "/webhook", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer s")
		h(httptest.NewRecorder(), req)
	}
	if enqueued != 1 {
		t.Fatalf("host-level group-deduped: enqueued=%d, want 1", enqueued)
	}
}

func TestHandleWebhook_StormRecordIncrementsAfterCooldownCheck(t *testing.T) {
	cm := shared.NewCooldownManager()
	enqueue := func(shared.AlertPayload) bool { return true }
	storm := shared.NewStormDetector(10000, time.Now)
	cfg := Config{WebhookSecret: "s", CooldownSeconds: 60}
	h := HandleWebhook(cfg, cm, enqueue, &shared.AlertMetrics{}, storm, shared.NewNopHistoryStore())

	for i := 1; i <= 3; i++ {
		body := fmt.Sprintf(`{"hostname":"h%d","service_description":"CPU","service_state":"WARNING","notification_type":"PROBLEM"}`, i)
		req := httptest.NewRequest("POST", "/webhook", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer s")
		h(httptest.NewRecorder(), req)
	}
	if got := storm.Count(); got != 3 {
		t.Fatalf("storm.Count()=%d, want 3", got)
	}

	// Same fingerprint → cooldown → NOT recorded
	body := `{"hostname":"h1","service_description":"CPU","service_state":"WARNING","notification_type":"PROBLEM"}`
	req := httptest.NewRequest("POST", "/webhook", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer s")
	h(httptest.NewRecorder(), req)
	if got := storm.Count(); got != 3 {
		t.Fatalf("after cooldown-dedup, storm.Count()=%d, want 3", got)
	}
}

func TestGroupKeyFromNotif(t *testing.T) {
	cases := []struct {
		name string
		n    CheckMKNotification
		want string
	}{
		{
			name: "service present",
			n:    CheckMKNotification{Hostname: "web01", ServiceDescription: "CPU"},
			want: "5:web013:CPU",
		},
		{
			name: "empty service uses _host_ sentinel",
			n:    CheckMKNotification{Hostname: "web01", ServiceDescription: ""},
			want: "5:web016:_host_",
		},
		{
			name: "empty hostname",
			n:    CheckMKNotification{Hostname: "", ServiceDescription: "Disk /"},
			want: "0:6:Disk /",
		},
		{
			name: "both empty",
			n:    CheckMKNotification{Hostname: "", ServiceDescription: ""},
			want: "0:6:_host_",
		},
		{
			// CheckMK ServiceDescriptions commonly contain ":" (e.g.
			// "Disk: /var"). Length-prefixing ensures these two notifications
			// — which would both produce "web01:Disk: /var" under a plain
			// join — yield distinct group keys.
			name: "service description containing colon",
			n:    CheckMKNotification{Hostname: "web01", ServiceDescription: "Disk: /var"},
			want: "5:web0110:Disk: /var",
		},
		{
			name: "colon in hostname",
			n:    CheckMKNotification{Hostname: "web01:Disk", ServiceDescription: " /var"},
			want: "10:web01:Disk5: /var",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := groupKeyFromNotif(tc.n)
			if got != tc.want {
				t.Errorf("groupKeyFromNotif(%+v) = %q, want %q", tc.n, got, tc.want)
			}
		})
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

	body := `{"hostname":"h1","service_description":"CPU","notification_type":"PROBLEM","service_state":"CRITICAL"}`
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
