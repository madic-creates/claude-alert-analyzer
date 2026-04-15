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
	regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`),
}

func RedactSecrets(input string) string {
	result := input
	for _, re := range sensitivePatterns {
		result = re.ReplaceAllString(result, "[REDACTED]")
	}
	return result
}

func Truncate(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	// Trim to a valid UTF-8 boundary to avoid splitting multi-byte characters.
	trimmed := strings.ToValidUTF8(s[:maxBytes], "")
	return trimmed + "\n... [truncated]"
}

func TruncateLines(s string, maxLines int) string {
	lines := splitLines(s)
	if len(lines) <= maxLines {
		return s
	}
	result := ""
	for i := 0; i < maxLines; i++ {
		result += lines[i] + "\n"
	}
	return result + "... [truncated]"
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
