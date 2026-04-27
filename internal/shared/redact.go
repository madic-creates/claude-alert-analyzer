package shared

import (
	"regexp"
	"strings"
	"unicode"
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
	// HTTP Authorization headers: redact everything after "Authorization:" to
	// end-of-line regardless of the auth scheme (Basic, Bearer, Token, ApiKey,
	// Digest, AWS4-HMAC-SHA256, …). This must run BEFORE the generic
	// keyword=value pattern below because that pattern only captures the first
	// non-whitespace word after the colon as the value — e.g. for
	// "Authorization: Token mysecret" it would replace "Token" and leave
	// "mysecret" unredacted. By consuming everything up to end-of-line we
	// prevent partial redactions like "Authorization: [REDACTED] mysecret"
	// that expose the actual credential after the scheme word is replaced.
	// Group 1 captures the leading non-letter character (or start of string) and
	// group 2 captures the keyword so both are preserved in the replacement.
	// The auth scheme is intentionally dropped alongside the credential to avoid
	// leaking the authentication mechanism.
	{
		re:          regexp.MustCompile(`(?i)(^|[^a-zA-Z])(authorization)\s*:\s*\S[^\n\r]*`),
		replacement: "${1}${2}: [REDACTED]",
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
	// Compound key names (access_token, api_key, client_secret, etc.) are listed
	// first because they are more specific than the single-keyword entries at the
	// end of the alternation. OAuth2 and cloud-provider API error responses
	// routinely include these compound names as JSON keys; without this
	// extension the generic keyword=value pattern below cannot catch them because
	// the closing double-quote after the key name is not whitespace and therefore
	// does not satisfy the \s*[=:] separator check.
	{
		re:          regexp.MustCompile(`(?i)"(access_token|refresh_token|id_token|api_key|secret_key|private_key|signing_key|auth_token|access_key|client_secret|api_secret|password|passwd|secret|token|key|authorization|bearer)"(\s*:\s*)"[^"]*"`),
		replacement: `"${1}"${2}"[REDACTED]"`,
	},
	// Keyword=value pairs: require the keyword not to be immediately preceded by
	// a letter so that words ending in a keyword suffix (e.g. "monkey", "donkey",
	// "hockey" which all end in "key") are not partially redacted. The leading
	// non-letter character (group 1) and the keyword name (group 2) are preserved
	// in the replacement; only the value after the separator is redacted.
	// Underscore is not a letter, so _key / api_key / API_KEY still match.
	// The separator (group 3) is captured and preserved so that
	// "api_key=secret" → "api_key=[REDACTED]" rather than "api_[REDACTED]",
	// making redacted output more informative for operators while still hiding
	// the sensitive value. This is consistent with the JSON key-value pattern
	// above, which also preserves the key name in its replacement.
	{
		re:          regexp.MustCompile(`(?i)(^|[^a-zA-Z])(password|passwd|secret|token|key|authorization|bearer)(\s*[=:]\s*)\S+`),
		replacement: "${1}${2}${3}[REDACTED]",
	},
	// Stripe secret keys (sk_live_/sk_test_) and restricted keys
	// (rk_live_/rk_test_) use underscores as separators, so they do not match
	// the sk- (hyphen) prefix above. They commonly appear in application error
	// logs when a Stripe API call fails (e.g. "invalid API key: sk_live_xxx"),
	// which CheckMK service checks and Kubernetes pod logs then capture and feed
	// into Claude's context.
	// GitHub token prefixes: ghp_ (classic PATs), gho_ (OAuth), ghs_ (GitHub
	// App server-to-server installation tokens), ghu_ (user-to-server tokens),
	// ghr_ (refresh tokens), github_pat_ (fine-grained PATs). All five gh*_
	// short-prefix forms appear in application logs when GitHub API calls fail
	// (e.g. authentication errors, expired installation tokens). ghs_ tokens
	// are commonly found in Kubernetes pod logs for deployments that use GitHub
	// App credentials via mounted secrets.
	// Slack token prefixes: xoxb- (bot), xoxp- (user/legacy), xoxa- (app-level),
	// xoxs- (workspace), xoxe- (Enterprise Grid), xoxr- (refresh). The original
	// xox[bpas]- pattern missed xoxe- and xoxr-, both of which are valid Slack
	// API credentials that appear in application logs on auth failures.
	// HashiCorp Vault token prefixes: hvs. (service tokens, the most common
	// type — issued by vault login, AppRole, and Kubernetes auth methods) and
	// hvb. (batch tokens — lightweight, non-renewable tokens used for
	// high-throughput workloads). Both appear in application logs when a Vault
	// API call fails with a 403 (e.g. "permission denied: token=hvs.xxx") or
	// when a Vault agent sidecar fails to authenticate and logs the raw token.
	// Kubernetes deployments using Vault Agent Injector or the Vault Secrets
	// Operator frequently surface these tokens in pod logs and events. The dot
	// separator is escaped as \. in the raw string so it matches a literal dot
	// rather than any character.
	{
		re:          regexp.MustCompile(`(?i)(sk-ant-|sk-|sk_live_|sk_test_|rk_live_|rk_test_|ghp_|gho_|ghs_|ghu_|ghr_|github_pat_|xox[bpaers]-|hvs\.|hvb\.)\S+`),
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
		re:          regexp.MustCompile(`(?i)(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?)://[^:\s/]*:[^@\s]+@\S+`),
		replacement: "[REDACTED]",
	},
	// AWS access key IDs: AKIA prefix for long-term IAM user keys and ASIA
	// prefix for short-term STS-generated keys (AssumeRole, GetFederationToken,
	// IRSA in Kubernetes). Both are 20 characters total (4-char prefix + 16
	// uppercase alphanumeric chars) and appear in application logs when AWS SDK
	// calls fail with authentication errors.
	{
		re:          regexp.MustCompile(`(AKIA|ASIA)[0-9A-Z]{16}`),
		replacement: "[REDACTED]",
	},
	// Email addresses: the domain section (between @ and the final dot) must
	// contain at least one letter so that systemd template unit names of the
	// form "user@<uid>.service" (e.g. "user@1000.service", "polkitd@0.service")
	// are not incorrectly redacted. Real email hostnames always contain at
	// least one letter; UID-based systemd instance identifiers are purely
	// numeric and must not be suppressed, as they are essential diagnostic
	// context in systemd journal output fed to Claude for root-cause analysis.
	{
		re:          regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]*[A-Za-z][A-Za-z0-9.-]*\.[A-Za-z]{2,}`),
		replacement: "[REDACTED]",
	},
}

// SanitizeOutput strips control characters from multi-line output while
// preserving newlines and tabs, before the output is injected into the Claude
// prompt. Multi-line diagnostic output (e.g. pod logs, plugin output) is
// expected to be formatted text, so newlines and tabs must be kept intact.
// However, carriage returns, null bytes, ESC (and other C0 characters), DEL,
// and C1 Unicode control characters (U+0080–U+009F) are stripped — they serve
// no diagnostic purpose and could be used to corrupt prompt formatting (e.g.
// ANSI escape sequences) or for terminal-side prompt injection techniques.
// This mirrors the sanitization applied by the CheckMK context gatherer to
// long_plugin_output.
func SanitizeOutput(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\t' || r == '\n' || !unicode.IsControl(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// SanitizeAlertField strips all control characters from a single-line alert
// field value before it is injected into a Claude prompt. Fields like alert
// names, severities, and statuses are expected to be single-line identifiers;
// embedded newlines or other control characters could inject fake Markdown
// sections into the prompt (prompt injection). This mirrors the sanitization
// applied by the CheckMK context gatherer to its single-line alert fields.
func SanitizeAlertField(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if !unicode.IsControl(r) {
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
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
