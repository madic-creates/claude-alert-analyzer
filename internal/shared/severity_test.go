package shared

import "testing"

func TestSeverityFromAlertmanager(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
		want   Severity
	}{
		{"critical", map[string]string{"severity": "critical"}, SeverityCritical},
		{"page", map[string]string{"severity": "page"}, SeverityCritical},
		{"warning", map[string]string{"severity": "warning"}, SeverityWarning},
		{"notice", map[string]string{"severity": "notice"}, SeverityWarning},
		{"info", map[string]string{"severity": "info"}, SeverityInfo},
		{"unknown_label_defaults_to_warning", map[string]string{"severity": "weird"}, SeverityWarning},
		{"missing_label_defaults_to_warning", map[string]string{}, SeverityWarning},
		{"case_insensitive", map[string]string{"severity": "CRITICAL"}, SeverityCritical},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SeverityFromAlertmanager(tt.labels); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSeverityFromCheckMK(t *testing.T) {
	tests := []struct {
		name         string
		serviceState string
		hostState    string
		want         Severity
	}{
		{"service_critical", "CRITICAL", "", SeverityCritical},
		{"service_warning", "WARNING", "", SeverityWarning},
		{"service_unknown", "UNKNOWN", "", SeverityUnknown},
		{"service_ok", "OK", "", SeverityInfo},
		{"service_ok_overrides_host_down", "OK", "DOWN", SeverityInfo},
		{"host_down", "", "DOWN", SeverityCritical},
		{"host_unreachable", "", "UNREACHABLE", SeverityCritical},
		{"host_up", "", "UP", SeverityInfo},
		{"empty_both_defaults_to_warning", "", "", SeverityWarning},
		// The next three cases verify that a known serviceState takes precedence
		// over a conflicting hostState. Removing any serviceState case from the
		// first switch would fall through to the hostState switch and return an
		// incorrect Severity — silently misrouting CheckMK alerts. The existing
		// "service_ok_overrides_host_down" covers "OK"; these three close the gap
		// for UNKNOWN, WARNING, and CRITICAL.
		{"unknown_service_overrides_down_host", "UNKNOWN", "DOWN", SeverityUnknown},
		{"warning_service_overrides_down_host", "WARNING", "DOWN", SeverityWarning},
		{"critical_service_overrides_up_host", "CRITICAL", "UP", SeverityCritical},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SeverityFromCheckMK(tt.serviceState, tt.hostState); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SeverityCritical, "critical"},
		{SeverityWarning, "warning"},
		{SeverityInfo, "info"},
		{SeverityUnknown, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.sev.String(); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSeverityNtfyPriority(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SeverityCritical, "5"},
		{SeverityWarning, "4"},
		{SeverityInfo, "2"},
		{SeverityUnknown, "3"},
	}
	for _, tt := range tests {
		t.Run(tt.sev.String(), func(t *testing.T) {
			if got := tt.sev.NtfyPriority(); got != tt.want {
				t.Errorf("NtfyPriority() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestParseSeverity verifies that parseSeverity is the exact inverse of
// Severity.String() for every defined Severity value and that an unrecognised
// string falls back to SeverityUnknown.
func TestParseSeverity(t *testing.T) {
	cases := []struct {
		in   string
		want Severity
	}{
		{"critical", SeverityCritical},
		{"warning", SeverityWarning},
		{"info", SeverityInfo},
		{"unknown", SeverityUnknown},
		{"", SeverityUnknown},
		{"CRITICAL", SeverityUnknown}, // case-sensitive: unrecognised → Unknown
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := parseSeverity(c.in); got != c.want {
				t.Errorf("parseSeverity(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}
