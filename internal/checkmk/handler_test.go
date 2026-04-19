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

func TestCheckmkHandleWebhook_UnauthorizedWrongToken(t *testing.T) {
	cfg := makeCheckmkConfig()
	cd := shared.NewCooldownManager()
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool { return true }, nil)

	notif := makeNotification("host1", "CPU", "WARNING", "PROBLEM")
	rr := postCheckmkWebhook(t, handler, "wrong-secret", notif)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCheckmkHandleWebhook_InvalidJSON(t *testing.T) {
	cfg := makeCheckmkConfig()
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

func TestCheckmkHandleWebhook_SkipsRecovery(t *testing.T) {
	cfg := makeCheckmkConfig()
	cd := shared.NewCooldownManager()
	var enqueued atomic.Int32
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		return true
	}, nil)

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
	}, nil)

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
	}, nil)

	// FLAPPING START: should be enqueued and set a cooldown keyed on "FLAPPING START".
	flap := makeNotification("host1", "Disk", "WARNING", "FLAPPING START")
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

func TestCheckmkHandleWebhook_EnqueuesProblem(t *testing.T) {
	cfg := makeCheckmkConfig()
	cd := shared.NewCooldownManager()
	var received shared.AlertPayload
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		received = ap
		return true
	}, nil)

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
			}, nil)
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
	}, nil)

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
	metrics := new(shared.AlertMetrics)
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		return true
	}, metrics)

	notif := makeNotification("host1", "CPU", "WARNING", "PROBLEM")

	postCheckmkWebhook(t, handler, "test-secret", notif)
	if metrics.AlertsCooldown.Load() != 0 {
		t.Errorf("expected 0 cooldown skips after first request, got %d", metrics.AlertsCooldown.Load())
	}

	postCheckmkWebhook(t, handler, "test-secret", notif)
	if metrics.AlertsCooldown.Load() != 1 {
		t.Errorf("expected 1 cooldown skip after duplicate request, got %d", metrics.AlertsCooldown.Load())
	}
}

func TestCheckmkHandleWebhook_QueueFull_Returns503(t *testing.T) {
	cfg := makeCheckmkConfig()
	cd := shared.NewCooldownManager()
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		return false // queue always full
	}, nil)

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
	}, nil)
	notif := makeNotification("host1", "Disk", "CRITICAL", "PROBLEM")
	postCheckmkWebhook(t, handler, "test-secret", notif)

	// Second attempt with working queue: should succeed (cooldown cleared)
	var enqueued atomic.Int32
	handler2 := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		return true
	}, nil)
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
	}, nil)

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
	}, nil)

	notif := makeNotification("host1", "CPU", "WARNING", "PROBLEM")
	postCheckmkWebhook(t, handler, "test-secret", notif)
	if received.Fingerprint == "" {
		t.Error("expected non-empty fingerprint")
	}
}

func TestCheckmkHandleWebhook_BodyTooLarge_Returns413(t *testing.T) {
	cfg := makeCheckmkConfig()
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

func TestCheckmkHandleWebhook_HostDown_SeverityCritical(t *testing.T) {
	// Host-level notification: ServiceState is empty, HostState is "DOWN".
	// Must produce severity "critical", not the default "warning".
	cfg := makeCheckmkConfig()
	cd := shared.NewCooldownManager()
	var got shared.AlertPayload
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		got = ap
		return true
	}, nil)

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

func TestCheckmkHandleWebhook_HostUnreachable_SeverityCritical(t *testing.T) {
	cfg := makeCheckmkConfig()
	cd := shared.NewCooldownManager()
	var got shared.AlertPayload
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		got = ap
		return true
	}, nil)

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

func TestCheckmkHandleWebhook_HostRecovery_ClearsCooldown(t *testing.T) {
	// Host-down PROBLEM sets a cooldown with empty ServiceState.
	// A subsequent RECOVERY must clear that cooldown so the next PROBLEM is analyzed.
	cfg := makeCheckmkConfig()
	cd := shared.NewCooldownManager()
	var enqueued atomic.Int32
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool {
		enqueued.Add(1)
		return true
	}, nil)

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
	if len(fp) != 16 {
		t.Errorf("expected fingerprint length 16, got %d", len(fp))
	}
}
