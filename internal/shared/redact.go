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
	// The underscore in each compound name is optional (_?) so that camelCase
	// variants (accessToken, apiKey, clientSecret, etc.) are also redacted.
	// Combined with the (?i) flag this covers snake_case, SCREAMING_SNAKE_CASE,
	// camelCase, and PascalCase variants of every compound key name.
	{
		re:          regexp.MustCompile(`(?i)"(access_?token|refresh_?token|id_?token|api_?key|secret_?key|private_?key|signing_?key|auth_?token|access_?key|client_?secret|api_?secret|password|passwd|secret|token|key|authorization|bearer)"(\s*:\s*)"[^"]*"`),
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
	// Credential-bearing connection URLs must come before the vendor prefix
	// pattern AND before the generic email pattern. Running before vendor
	// prefixes is required because some vendor tokens (e.g. SendGrid's SG.
	// prefix) can appear as passwords inside credential URLs
	// (e.g. smtps://apikey:SG.xxx@smtp.sendgrid.net). The vendor prefix
	// pattern uses \S+ which greedily consumes SG.xxx@smtp.sendgrid.net
	// (including the @ and hostname), preventing the URL pattern from ever
	// seeing the full scheme://user:pass@host structure. Running the URL
	// pattern first captures the entire credential URL as a unit, so the
	// vendor prefix pattern has nothing left to partially consume.
	// Running before the email pattern is required because the user:pass@host
	// portion would otherwise be partially consumed by the email regex
	// (matching pass@host), leaving the username unredacted. The username
	// group uses * (zero-or-more) instead of + so that password-only URLs
	// (e.g. redis://:secret@host) are also redacted.
	// Redis commonly uses an empty username; when the host is an IP address the
	// email-fallback cannot help because it requires a letter-only TLD.
	//
	// SMTP/SMTPS appear in application logs when email delivery fails (Django,
	// Rails, Spring Boot). The existing email-fallback catches the password
	// (matching password@host) but leaves the SMTP username unredacted; this
	// pattern replaces the entire credential-bearing URL as a unit.
	// LDAP/LDAPS bind DNs (cn=admin,dc=example,dc=com:password@host) follow the
	// same scheme://user:pass@host structure and are similarly covered by
	// replacing the full URL rather than relying on the email pattern to save the
	// password component.
	// NATS (nats://) is a cloud-native messaging system widely used in Kubernetes
	// microservice architectures. When authentication fails, NATS client libraries
	// log the full connection URL including credentials (e.g. "nats: connect to
	// [nats://user:secret@nats-cluster:4222]: Authorization violation"). The
	// keyword=value pattern does not catch bare NATS URLs because the scheme name
	// (NATS_URL) is not in its keyword list; the email-fallback cannot help either
	// because the host portion often lacks a letter-only TLD.
	// SQL Server (sqlserver://, mssql://) connection URLs appear in pod logs when
	// an enterprise workload fails to connect to a Microsoft SQL Server instance.
	// The go-mssqldb driver (github.com/microsoft/go-mssqldb) uses
	// sqlserver://user:password@hostname:1433?database=dbname; older forks and the
	// denisenkom driver also accept mssql://. Neither scheme name appears in the
	// keyword=value keyword list (the env var is typically DATABASE_URL or
	// DB_CONNECTION_STRING, both absent from the list), so without this URL
	// pattern the full credential-bearing URL would reach the Claude API unredacted.
	// ClickHouse (clickhouse://) is a column-oriented analytics database widely used
	// as an observability data store (Signoz, Quickwit, Infra backends). The
	// official ClickHouse Go driver v2 (github.com/ClickHouse/clickhouse-go) uses
	// clickhouse://user:password@host:9000/database for the native TCP protocol.
	// When authentication fails — e.g. "exception: Code: 516. DB::Exception:
	// clickhouse://svcuser:s3cr3t@clickhouse:9000/ops: Authentication failed" — the
	// full credential URL is included in the error message. Neither clickhouse nor
	// any typical env var name (CLICKHOUSE_URL, CLICKHOUSE_DSN) appears in the
	// keyword=value list, so without this entry the credentials reach Claude.
	// HTTP/HTTPS (https?://) credential-bearing URLs appear when a webhook receiver,
	// Prometheus remote_write endpoint, or internal API client logs a connection
	// failure that includes the full request URL. Go's net/http library includes the
	// full URL in transport-layer error messages — e.g. "dial tcp: lookup
	// https://svcacct:hunter2@monitoring.corp.example.com: no such host" — exposing
	// both username and password. The existing email pattern (pattern 10) catches the
	// password component (matching "hunter2@monitoring.corp.example.com") but leaves
	// the username unredacted, producing partial output like "https://svcacct:[REDACTED]"
	// that still reveals the service account identity. Adding https? replaces the entire
	// credential-bearing URL as a unit. Plain URLs without credentials (e.g.
	// "https://api.example.com") are not affected — the pattern requires user:pass@.
	{
		re:          regexp.MustCompile(`(?i)(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?|smtps?|ldaps?|nats|sqlserver|mssql|clickhouse|https?)://[^:\s/]*:[^@\s]+@\S+`),
		replacement: "[REDACTED]",
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
	// GitLab token prefixes: glpat- (personal access tokens), glrrt- (runner
	// registration tokens), glrt- (runner authentication tokens), gldt- (deploy
	// tokens), glsoat- (service account tokens), glagent- (agent tokens). These
	// appear in pod logs when GitLab CI/CD pipeline credentials or image-pull
	// secrets are logged on authentication failures (e.g. "UNAUTHORIZED: GitLab:
	// token glpat-xxx is invalid"). Docker Hub PAT prefix dckr_pat_ appears in
	// image-pull error logs when a Docker Hub personal access token is rejected.
	// SendGrid API keys (SG.) use a two-part dot-separated base64url format
	// (SG.<22-char>.<43-char>) and appear in application pod logs when email
	// delivery fails (Django EMAIL_BACKEND=sendgrid, Rails ActionMailer with
	// sendgrid-ruby, Spring Boot with sendgrid-java) and the SendGrid API
	// rejects the key (e.g. "SendGrid API error: 403 Forbidden — key SG.xxx").
	// npm access tokens (npm_) are 36-character alphanumeric strings that appear
	// in Node.js pod logs and CI/CD pipeline logs when npm registry authentication
	// fails (e.g. "npm ERR! code E401 … token npm_xxx is invalid") or when an
	// .npmrc file with an embedded token is printed in a build error trace.
	// HuggingFace access tokens (hf_) are ~36-character alphanumeric strings
	// issued by huggingface.co for model repository and Inference API access.
	// They appear in ML serving pod logs when a model download or Inference API
	// call fails authentication (e.g. "authentication failed for token hf_QNT…").
	// The keyword=value pattern above does not catch bare occurrences like
	// "token hf_xxx" because its separator requires '=' or ':' — a plain space
	// before the token value is not matched. This prefix pattern fills that gap.
	// Databricks personal access tokens (dapi) are ~32-character hex strings
	// used to authenticate against Databricks REST APIs (MLflow tracking, model
	// serving, Feature Store, Unity Catalog). They appear in ML workload pod logs
	// when a Databricks API call fails (e.g. "Error: 403 Forbidden, token=dapi…"
	// or "databricks.sdk: authentication failed with token dapi…"). Like hf_
	// tokens, bare occurrences use a space separator and are not caught by the
	// keyword=value pattern above.
	// DigitalOcean personal access tokens (dop_v1_) are 64-character hex strings
	// used to authenticate against the DigitalOcean API and the DigitalOcean
	// Container Registry (DOCR). They appear in DOKS (DigitalOcean Kubernetes
	// Service) pod logs when a registry pull fails (e.g. "failed to authenticate
	// with registry: token dop_v1_xxx is invalid") or when a Flux/ArgoCD CD
	// controller logs a DigitalOcean API call failure. Like hf_ and dapi tokens,
	// bare occurrences use a space separator and are not caught by the
	// keyword=value pattern above.
	// Grafana Cloud service account tokens (glsa_) are ~40-character hex strings
	// used to authenticate datasource connections, recording rules, and
	// remote_write integrations with Grafana Cloud (Mimir, Loki, Tempo). They
	// appear in pod logs when a Prometheus remote_write endpoint or Grafana Agent
	// rejects the token (e.g. "remote_write: authentication error: Bearer
	// glsa_xxx"). They share the gl* prefix family with GitLab tokens (glpat-,
	// glagent-, etc.) but are issued by Grafana, not GitLab. The keyword=value
	// pattern catches GRAFANA_TOKEN=... but bare space-separated occurrences are
	// not matched by it — this prefix pattern fills that gap.
	// Pulumi access tokens (pul-) are ~100-character base64url strings used to
	// authenticate with the Pulumi Cloud backend for state management and secrets.
	// They appear in Kubernetes CD pipeline pod logs when a pulumi up/destroy/
	// preview fails to authenticate (e.g. "error: PULUMI_ACCESS_TOKEN pul-xxx is
	// invalid"). The keyword=value pattern catches PULUMI_ACCESS_TOKEN=... but
	// bare occurrences with a space separator are not matched by it.
	// Tailscale auth keys (tskey- prefix) authenticate nodes — including
	// Kubernetes pods running the Tailscale sidecar via the Tailscale Operator or
	// EgressServices/IngressServices resources — to a Tailscale network (tailnet).
	// Key sub-types share the tskey- prefix: tskey-auth- (standard auth keys),
	// tskey-ephemeral- (single-use keys that auto-expire when the node disconnects),
	// and tskey-client- (OAuth client credentials). When a sidecar fails to
	// authenticate — e.g. "invalid auth key tskey-auth-xxx" or "tailscale up:
	// authentication failed: tskey-ephemeral-xxx" — the full key appears in the pod
	// log that CheckMK or Kubernetes feeds into Claude's context. The keyword=value
	// pattern catches TS_AUTHKEY=tskey-auth-... but bare space-separated occurrences
	// are not matched by it.
	// PlanetScale personal access tokens (pscale_tkn_) authenticate against the
	// PlanetScale database-as-a-service API (MySQL-compatible). They appear in
	// Kubernetes workload logs when a PlanetScale-backed application fails to
	// authenticate (e.g. "pscale: authentication failed: token pscale_tkn_xxx is
	// invalid" or "dial error: PlanetScale: unauthorized pscale_tkn_xxx"). The
	// keyword=value pattern catches PLANETSCALE_TOKEN=... but bare space-separated
	// occurrences are not matched by it.
	// Supabase personal access tokens (sbp_) authenticate against the Supabase
	// management API (PostgreSQL-compatible). They appear in Kubernetes workload
	// logs when a Supabase-backed application or a Supabase CLI pod fails to
	// authenticate (e.g. "supabase: invalid access token sbp_xxx" or "Error 401:
	// Unauthorized sbp_xxx"). The keyword=value pattern catches SUPABASE_ACCESS_TOKEN=...
	// but bare space-separated occurrences are not matched by it.
	{
		re:          regexp.MustCompile(`(?i)(sk-ant-|sk-|sk_live_|sk_test_|rk_live_|rk_test_|ghp_|gho_|ghs_|ghu_|ghr_|github_pat_|glpat-|glrrt-|glrt-|gldt-|glsoat-|glagent-|glsa_|dckr_pat_|SG\.|npm_|hf_|dapi|dop_v1_|pul-|tskey-|xox[bpaers]-|hvs\.|hvb\.|pscale_tkn_|sbp_)\S+`),
		replacement: "[REDACTED]",
	},
	{
		re:          regexp.MustCompile(`(?i)-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]*?-----END[A-Z ]*PRIVATE KEY-----`),
		replacement: "[REDACTED]",
	},
	// JWT tokens: every JWT header is a base64url-encoded JSON object that
	// starts with '{"', which encodes to "eyJ". Requiring two dot separators
	// (header.payload.signature) distinguishes full JWTs from short base64url
	// strings that happen to start with "eyJ". The signature segment uses *
	// (zero-or-more) to handle unsigned JWTs (alg="none") whose signature is
	// empty. This pattern catches JWTs that appear bare in log lines — e.g.
	// "token expired: eyJhbGci.payload.sig" — where neither the
	// Authorization-header pattern nor the "bearer" inline pattern would fire
	// because no keyword precedes the token. JWT payloads routinely contain
	// PII (sub, email, roles) and must not reach the Claude API in clear text.
	{
		re:          regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`),
		replacement: "[REDACTED]",
	},
	// Inline bearer/basic tokens that appear in log lines without an
	// "Authorization:" header prefix. The character class includes:
	//   A-Za-z0-9+/= — standard Base64 alphabet (opaque tokens, API keys)
	//   .            — JWT segment separator (header.payload.signature)
	//   -            — base64url and hyphenated token separators (RFC 4648 §5,
	//                  e.g. "my-service-token-abc123", "eyJ...", RFC 9068)
	//   _            — base64url alphabet (RFC 4648 §5, used by JWT and
	//                  many API key formats like Stripe's "sk_live_" keys)
	// Without these additions the pattern only redacts up to the first dot or
	// hyphen: a JWT like "bearer eyJhbGci.payload.sig" would leave the payload
	// segment (which may contain email, sub, roles) exposed as ".payload.sig",
	// and a hyphenated token like "bearer my-svc-key-abc123def456ghi789" would
	// not be redacted at all because the match stops at the first hyphen (2 chars
	// < the 20-character minimum). The Authorization-header pattern above catches
	// "Authorization: Bearer …" lines first; this pattern handles the remaining
	// cases where the token appears inline in log or diagnostic output.
	{
		re:          regexp.MustCompile(`(?i)(basic|bearer)\s+[A-Za-z0-9+/=._-]{20,}`),
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
// U+2028 (LINE SEPARATOR) and U+2029 (PARAGRAPH SEPARATOR) are also stripped:
// unicode.IsControl misses them, yet some renderers treat them as line breaks —
// the same prompt-injection vector as an embedded carriage return.
// This mirrors the sanitization applied by the CheckMK context gatherer to
// long_plugin_output.
func SanitizeOutput(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\t' || r == '\n' || (!unicode.IsControl(r) && r != '\u2028' && r != '\u2029') {
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
//
// U+2028 (LINE SEPARATOR) and U+2029 (PARAGRAPH SEPARATOR) are stripped
// explicitly because unicode.IsControl does not cover them, yet ECMAScript
// and some text renderers treat them as line breaks — the same prompt-injection
// vector as an embedded newline.
func SanitizeAlertField(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if !unicode.IsControl(r) && r != '\u2028' && r != '\u2029' {
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
