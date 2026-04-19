package shared

import (
	"regexp"
	"strings"
)

type sensitivePattern struct {
	re          *regexp.Regexp
	replacement string
}

// sensitivePatterns is an ordered list of patterns applied by RedactSecrets.
// Each entry pairs a compiled regexp with the replacement string to use.
// Patterns must be ordered so that more specific matches (e.g. DB URLs) run
// before broader ones (e.g. the email pattern) to avoid partial redactions.
var sensitivePatterns = []sensitivePattern{
	// Keyword=value pairs: require the keyword not to be immediately preceded by
	// a letter so that words ending in a keyword suffix (e.g. "monkey", "donkey",
	// "hockey" which all end in "key") are not partially redacted. The leading
	// non-letter character (group 1) is preserved in the replacement.
	// Underscore is not a letter, so _key / api_key / API_KEY still match.
	{
		re:          regexp.MustCompile(`(?i)(^|[^a-zA-Z])(password|passwd|secret|token|key|authorization|bearer)\s*[=:]\s*\S+`),
		replacement: "${1}[REDACTED]",
	},
	{
		re:          regexp.MustCompile(`(?i)(sk-ant-|sk-|ghp_|gho_|github_pat_|xox[bpas]-)\S+`),
		replacement: "[REDACTED]",
	},
	{
		re:          regexp.MustCompile(`(?i)-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]*?-----END[A-Z ]*PRIVATE KEY-----`),
		replacement: "[REDACTED]",
	},
	{
		re:          regexp.MustCompile(`(?i)(basic|bearer)\s+[A-Za-z0-9+/=]{20,}`),
		replacement: "[REDACTED]",
	},
	// DB connection strings must come before the generic email pattern, because
	// the user:pass@host portion of a URL would otherwise be partially consumed
	// by the email regex (matching pass@host), leaving the username unredacted.
	{
		re:          regexp.MustCompile(`(?i)(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/]+:[^@\s]+@\S+`),
		replacement: "[REDACTED]",
	},
	{
		re:          regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		replacement: "[REDACTED]",
	},
	{
		re:          regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`),
		replacement: "[REDACTED]",
	},
}

func RedactSecrets(input string) string {
	result := input
	for _, p := range sensitivePatterns {
		result = p.re.ReplaceAllString(result, p.replacement)
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

