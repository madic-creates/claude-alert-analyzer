package checkmk

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
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
	})

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
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool { return true })

	notif := makeNotification("host1", "CPU", "WARNING", "PROBLEM")
	rr := postCheckmkWebhook(t, handler, "wrong-secret", notif)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCheckmkHandleWebhook_InvalidJSON(t *testing.T) {
	cfg := makeCheckmkConfig()
	cd := shared.NewCooldownManager()
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool { return true })

	req := httptest.NewRequest("POST", "/webhook", bytes.NewReader([]byte(`not json`)))
	req.Header.Set("Authorization", "Bearer test-secret")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCheckmkHandleWebhook_SkipsRecovery(t *testing.T) {
	cfg := makeCheckmkConfig()
	cd := shared.NewCooldownManager()
	var enqueued atomic.Int32
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		return true
	})

	notif := makeNotification("host1", "CPU", "OK", "RECOVERY")
	rr := postCheckmkWebhook(t, handler, "test-secret", notif)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if enqueued.Load() != 0 {
		t.Errorf("expected 0 enqueued for recovery, got %d", enqueued.Load())
	}
}

func TestCheckmkHandleWebhook_EnqueuesProblem(t *testing.T) {
	cfg := makeCheckmkConfig()
	cd := shared.NewCooldownManager()
	var received shared.AlertPayload
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		received = ap
		return true
	})

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
			})
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
	})

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

func TestCheckmkHandleWebhook_QueueFull_Returns503(t *testing.T) {
	cfg := makeCheckmkConfig()
	cd := shared.NewCooldownManager()
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		return false // queue always full
	})

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
	})
	notif := makeNotification("host1", "Disk", "CRITICAL", "PROBLEM")
	postCheckmkWebhook(t, handler, "test-secret", notif)

	// Second attempt with working queue: should succeed (cooldown cleared)
	var enqueued atomic.Int32
	handler2 := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		return true
	})
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
	})

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
	})

	notif := makeNotification("host1", "CPU", "WARNING", "PROBLEM")
	postCheckmkWebhook(t, handler, "test-secret", notif)
	if received.Fingerprint == "" {
		t.Error("expected non-empty fingerprint")
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
	if len(fp) != 16 {
		t.Errorf("expected fingerprint length 16, got %d", len(fp))
	}
}
