package shared

import "strings"

// Severity is a normalized alert severity used for routing decisions.
type Severity int

const (
	SeverityUnknown Severity = iota
	SeverityInfo
	SeverityWarning
	SeverityCritical
)

// String returns the lowercase string label for the severity.
func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "critical"
	case SeverityWarning:
		return "warning"
	case SeverityInfo:
		return "info"
	default:
		return "unknown"
	}
}

// SeverityFromAlertmanager maps the Alertmanager `severity` label to a Severity.
// Unknown or missing labels default to SeverityWarning (defensive — we'd rather
// pay for an unnecessary analysis than silently downgrade a real critical).
func SeverityFromAlertmanager(labels map[string]string) Severity {
	switch strings.ToLower(labels["severity"]) {
	case "critical", "page":
		return SeverityCritical
	case "warning", "notice":
		return SeverityWarning
	case "info":
		return SeverityInfo
	default:
		return SeverityWarning
	}
}

// SeverityFromCheckMK maps CheckMK service/host state strings to a Severity.
// serviceState takes precedence; hostState is the fallback for host-level
// notifications where serviceState is empty.
func SeverityFromCheckMK(serviceState, hostState string) Severity {
	switch serviceState {
	case "CRITICAL":
		return SeverityCritical
	case "WARNING":
		return SeverityWarning
	case "UNKNOWN":
		return SeverityWarning
	}
	switch hostState {
	case "DOWN", "UNREACHABLE":
		return SeverityCritical
	}
	return SeverityWarning
}
