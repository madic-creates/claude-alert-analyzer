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
	// HTTP Authorization headers with a scheme (Basic or Bearer) followed by
	// credentials. This must run BEFORE the generic keyword=value pattern below
	// because that pattern only captures the first non-whitespace word after the
	// colon (e.g. it redacts "Authorization: Bearer" but leaves the actual token
	// on the next whitespace-delimited word unredacted). Once "Bearer" is consumed
	// by the generic pattern the token is no longer preceded by a scheme keyword
	// and escapes all subsequent patterns.
	{
		re:          regexp.MustCompile(`(?i)(^|[^a-zA-Z])(authorization)\s*:\s*(?:basic|bearer)\s+\S+`),
		replacement: "${1}[REDACTED]",
	},
	// JSON-style double-quoted key-value pairs: "password": "value". Monitoring
	// output and API error responses are often JSON-formatted, where the key is
	// wrapped in double quotes and separated from the string value by ": ".
	// The generic keyword=value pattern below cannot match this form because the
	// closing quote after the key name is not whitespace and breaks the \s*[=:]
	// match. Group 1 captures the keyword so the key name can be preserved in
	// the replacement; group 2 captures the separator so its whitespace is
	// preserved too. Must run before the generic pattern to avoid the generic
	// pattern partially consuming the closing key-quote.
	{
		re:          regexp.MustCompile(`(?i)"(password|passwd|secret|token|key|authorization|bearer)"(\s*:\s*)"[^"]*"`),
		replacement: `"${1}"${2}"[REDACTED]"`,
	},
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
	// The username group uses * (zero-or-more) instead of + (one-or-more) so
	// that password-only URLs (e.g. redis://:secret@host) are also redacted.
	// Redis commonly uses an empty username with a password-only auth string,
	// and when the host is an IP address the email-fallback pattern cannot save
	// the secret because it requires a letter-only TLD.
	{
		re:          regexp.MustCompile(`(?i)(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/]*:[^@\s]+@\S+`),
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
	if maxBytes <= 0 {
		return ""
	}
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

