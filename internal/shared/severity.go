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

// NtfyPriority returns the ntfy priority string for the severity level.
// ntfy priorities: 1=min, 2=low, 3=default, 4=high, 5=urgent (max).
func (s Severity) NtfyPriority() string {
	switch s {
	case SeverityCritical:
		return "5"
	case SeverityWarning:
		return "4"
	case SeverityInfo:
		return "2"
	default: // SeverityUnknown
		return "3"
	}
}

// parseSeverity converts the stored lowercase string back to a Severity.
// Used when reading rows written by Severity.String().
func parseSeverity(s string) Severity {
	switch s {
	case "critical":
		return SeverityCritical
	case "warning":
		return SeverityWarning
	case "info":
		return SeverityInfo
	default:
		return SeverityUnknown
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
		return SeverityUnknown
	case "OK":
		// Service is healthy; map to info so operators can route these
		// notifications through a lighter analysis policy (e.g.
		// MAX_AGENT_ROUNDS_INFO=0 for static-only) without affecting
		// problem-severity alerts.
		return SeverityInfo
	}
	switch hostState {
	case "DOWN", "UNREACHABLE":
		return SeverityCritical
	case "UP":
		return SeverityInfo
	}
	return SeverityWarning
}
