package shared

import (
	"regexp"
	"strings"
)

var sensitivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(password|passwd|secret|token|key|authorization|bearer)\s*[=:]\s*\S+`),
	regexp.MustCompile(`(?i)(sk-ant-|sk-|ghp_|gho_|github_pat_|xox[bpas]-)\S+`),
	regexp.MustCompile(`(?i)-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]*?-----END[A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)(basic|bearer)\s+[A-Za-z0-9+/=]{20,}`),
	// DB connection strings must come before the generic email pattern, because
	// the user:pass@host portion of a URL would otherwise be partially consumed
	// by the email regex (matching pass@host), leaving the username unredacted.
	regexp.MustCompile(`(?i)(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/]+:[^@\s]+@\S+`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`),
}

func RedactSecrets(input string) string {
	result := input
	for _, re := range sensitivePatterns {
		result = re.ReplaceAllString(result, "[REDACTED]")
	}
	return result
}

const truncationMarker = "\n... [truncated]"

func Truncate(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	// Reserve space for the marker so the total output stays within maxBytes.
	cutAt := maxBytes - len(truncationMarker)
	if cutAt <= 0 {
		return truncationMarker[:maxBytes]
	}
	// Trim to a valid UTF-8 boundary to avoid splitting multi-byte characters.
	trimmed := strings.ToValidUTF8(s[:cutAt], "")
	return trimmed + truncationMarker
}

