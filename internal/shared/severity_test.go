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
		{"service_unknown", "UNKNOWN", "", SeverityWarning},
		{"host_down", "", "DOWN", SeverityCritical},
		{"host_unreachable", "", "UNREACHABLE", SeverityCritical},
		{"host_ok_fallback", "", "UP", SeverityWarning},
		{"empty_both_defaults_to_warning", "", "", SeverityWarning},
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
