package shared

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRedactSecrets_Password(t *testing.T) {
	input := "password=secret123 other text"
	result := RedactSecrets(input)
	if result == input {
		t.Errorf("expected redaction, got: %s", result)
	}
	if strings.Contains(result, "secret123") {
		t.Errorf("secret not redacted: %s", result)
	}
	// The keyword name must be preserved so operators can identify which field
	// was redacted. Only the value is replaced, not the key=separator pair.
	if !strings.Contains(result, "password=") {
		t.Errorf("keyword name should be preserved in output, got: %s", result)
	}
}

func TestRedactSecrets_BearerToken(t *testing.T) {
	input := "Authorization: Bearer sk-ant-abc123def456ghi789jkl"
	result := RedactSecrets(input)
	if strings.Contains(result, "sk-ant-") {
		t.Errorf("bearer token not redacted: %s", result)
	}
}

// TestRedactSecrets_AuthorizationHeaderLabelPreserved verifies that the
// "Authorization" keyword is retained in the output after redaction, consistent
// with the keyword=value pattern which preserves the key name so operators can
// tell which field was redacted without exposing its value.
func TestRedactSecrets_AuthorizationHeaderLabelPreserved(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string // substring that MUST appear in redacted output
	}{
		{
			name:  "bearer token at start of line",
			input: "Authorization: Bearer mytoken123",
			want:  "Authorization: [REDACTED]",
		},
		{
			name:  "basic auth at start of line",
			input: "Authorization: Basic dXNlcjpwYXNz",
			want:  "Authorization: [REDACTED]",
		},
		{
			name:  "authorization header in curl command",
			input: "curl -H 'Authorization: Bearer tok456' https://api.example.com",
			want:  "Authorization: [REDACTED]",
		},
		{
			name:  "lowercase keyword preserved as-is",
			input: "authorization: bearer mytoken",
			want:  "authorization: [REDACTED]",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := RedactSecrets(tc.input)
			if !strings.Contains(result, tc.want) {
				t.Errorf("expected %q in redacted output:\n  input:  %s\n  output: %s", tc.want, tc.input, result)
			}
		})
	}
}

// TestRedactSecrets_BearerTokenShort verifies that a bearer token in an HTTP
// Authorization header is fully redacted even when the token is shorter than
// 20 characters and carries no known vendor prefix (e.g. sk-ant-, ghp_).
// Previously, the generic keyword=value pattern only captured "Bearer" (the
// first whitespace-delimited word) as the value, leaving the actual credential
// on the following word unredacted. The new Authorization-specific pattern
// must run before the generic one to catch the full "Bearer <token>" value.
func TestRedactSecrets_BearerTokenShort(t *testing.T) {
	cases := []struct {
		name  string
		input string
		leak  string // substring that must NOT appear in result
	}{
		{
			name:  "short token no prefix",
			input: "Authorization: Bearer MyAppToken12",
			leak:  "MyAppToken12",
		},
		{
			name:  "short token in curl command",
			input: "curl -H 'Authorization: Bearer abc123' https://api.example.com",
			leak:  "abc123",
		},
		{
			name:  "basic auth credentials",
			input: "Authorization: Basic dXNlcjpwYXNz",
			leak:  "dXNlcjpwYXNz",
		},
		{
			name:  "long token without known prefix",
			input: "Authorization: Bearer MyLongToken123456789",
			leak:  "MyLongToken123456789",
		},
		{
			name:  "case insensitive scheme",
			input: "authorization: bearer InternalServiceKey99",
			leak:  "InternalServiceKey99",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := RedactSecrets(tc.input)
			if strings.Contains(result, tc.leak) {
				t.Errorf("token leaked in output:\n  input:  %s\n  output: %s\n  leaked: %s", tc.input, result, tc.leak)
			}
			if !strings.Contains(result, "[REDACTED]") {
				t.Errorf("expected [REDACTED] marker in output, got: %s", result)
			}
		})
	}
}

// TestRedactSecrets_NonBearerAuthSchemes verifies that Authorization headers
// using schemes other than Basic/Bearer (e.g. Token, ApiKey, Digest) are fully
// redacted. Previously only Basic and Bearer were matched by the first pattern;
// other schemes fell through to the keyword=value pattern which only consumed
// the scheme word, leaving the actual credential on the next token unredacted
// (e.g. "Authorization: Token mysecret" → "Authorization: [REDACTED] mysecret").
func TestRedactSecrets_NonBearerAuthSchemes(t *testing.T) {
	cases := []struct {
		name  string
		input string
		leak  string // substring that must NOT appear in result
	}{
		{
			name:  "Token scheme",
			input: "Authorization: Token mysecrettoken123",
			leak:  "mysecrettoken123",
		},
		{
			name:  "ApiKey scheme",
			input: "Authorization: ApiKey abc-def-ghi-jkl",
			leak:  "abc-def-ghi-jkl",
		},
		{
			name:  "Digest scheme partial credentials",
			input: `Authorization: Digest username="alice", realm="example.com", response="deadbeef"`,
			leak:  "deadbeef",
		},
		{
			name:  "Token scheme in log line",
			input: `request failed: status=401 header="Authorization: Token secret99"`,
			leak:  "secret99",
		},
		{
			name:  "case-insensitive token scheme",
			input: "authorization: token MYTOKEN456",
			leak:  "MYTOKEN456",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := RedactSecrets(tc.input)
			if strings.Contains(result, tc.leak) {
				t.Errorf("credential leaked in output:\n  input:  %s\n  output: %s\n  leaked: %s", tc.input, result, tc.leak)
			}
			if !strings.Contains(result, "[REDACTED]") {
				t.Errorf("expected [REDACTED] marker in output, got: %s", result)
			}
		})
	}
}

func TestRedactSecrets_PrivateKey(t *testing.T) {
	input := "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
	result := RedactSecrets(input)
	if strings.Contains(result, "MIIE") {
		t.Errorf("private key not redacted: %s", result)
	}
}

func TestRedactSecrets_AWSAccessKeyID(t *testing.T) {
	input := "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
	result := RedactSecrets(input)
	if strings.Contains(result, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("AWS access key ID not redacted: %s", result)
	}
}

func TestRedactSecrets_AWSKeyInText(t *testing.T) {
	input := "Using key AKIAI44QH8DHBEXAMPLE for upload"
	result := RedactSecrets(input)
	if strings.Contains(result, "AKIAI44QH8DHBEXAMPLE") {
		t.Errorf("AWS access key not redacted in free text: %s", result)
	}
}

func TestRedactSecrets_PostgresURL(t *testing.T) {
	input := "DATABASE_URL=postgres://myuser:s3cr3t@db.example.com:5432/mydb"
	result := RedactSecrets(input)
	if strings.Contains(result, "s3cr3t") {
		t.Errorf("postgres credentials not redacted: %s", result)
	}
	if strings.Contains(result, "myuser") {
		t.Errorf("postgres username not redacted: %s", result)
	}
}

func TestRedactSecrets_MySQLURL(t *testing.T) {
	input := "connect to mysql://root:hunter2@localhost/app"
	result := RedactSecrets(input)
	if strings.Contains(result, "hunter2") {
		t.Errorf("mysql credentials not redacted: %s", result)
	}
}

func TestRedactSecrets_RedisURL(t *testing.T) {
	input := "cache: redis://:supersecret@redis.internal:6379/0"
	result := RedactSecrets(input)
	if strings.Contains(result, "supersecret") {
		t.Errorf("redis credentials not redacted: %s", result)
	}
}

// TestRedactSecrets_RedisURLWithIP verifies that a password-only Redis URL
// (empty username) pointing at an IP address is redacted. The DB URL pattern
// previously used [^:\s/]+ (one-or-more chars before the colon), so an empty
// username bypassed it. The email-fallback pattern cannot rescue this case
// because IP addresses have no letter-only TLD. The bug only surfaced in
// production when Redis was configured without a username (common in Redis <
// 6.0 where only a password was supported) and the connection string pointed
// at a private IP address rather than a DNS hostname.
func TestRedactSecrets_RedisURLWithIPAndEmptyUser(t *testing.T) {
	cases := []struct {
		name  string
		input string
		leak  string
	}{
		{
			name:  "empty username with IPv4 host",
			input: "REDIS_URL=redis://:s3cr3t@192.168.1.100:6379/0",
			leak:  "s3cr3t",
		},
		{
			name:  "empty username with hostname",
			input: "cache: redis://:p%40ssword@redis.internal:6379/1",
			leak:  "p%40ssword",
		},
		{
			name:  "amqp empty user with IP",
			input: "amqp://:rabbit_secret@10.0.0.5:5672/vhost",
			leak:  "rabbit_secret",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := RedactSecrets(tc.input)
			if strings.Contains(result, tc.leak) {
				t.Errorf("credential leaked:\n  input:  %s\n  output: %s", tc.input, result)
			}
			if !strings.Contains(result, "[REDACTED]") {
				t.Errorf("expected [REDACTED] marker in output: %s", result)
			}
		})
	}
}

func TestRedactSecrets_MongoDBURL(t *testing.T) {
	input := "uri: mongodb+srv://admin:p%40ss@cluster0.example.net/mydb"
	result := RedactSecrets(input)
	if strings.Contains(result, "p%40ss") {
		t.Errorf("mongodb credentials not redacted: %s", result)
	}
}

// TestRedactSecrets_TLSSchemeVariants verifies that TLS variants of connection
// URL schemes (amqps://, rediss://) are redacted like their non-TLS counterparts.
// amqps is the standard TLS scheme for RabbitMQ/AMQP 0-9-1 and is commonly
// found in Kubernetes secret mounts and pod environment variables. rediss is
// the TLS scheme used by several Go Redis clients (e.g. go-redis, redigo with
// TLS URL helpers). Before this fix only the bare amqp:// and redis:// schemes
// were matched; the TLS variants would leak credentials into Claude prompts.
func TestRedactSecrets_TLSSchemeVariants(t *testing.T) {
	cases := []struct {
		name  string
		input string
		leak  string
	}{
		{
			name:  "amqps with credentials",
			input: "AMQP_URL=amqps://user:tls_password@rabbit.internal:5671/vhost",
			leak:  "tls_password",
		},
		{
			name:  "amqps empty username with IP",
			input: "amqps://:rabbit_tls_secret@10.0.0.5:5671/vhost",
			leak:  "rabbit_tls_secret",
		},
		{
			name:  "rediss with credentials",
			input: "REDIS_URL=rediss://default:tls_secret@redis.internal:6380/0",
			leak:  "tls_secret",
		},
		{
			name:  "rediss empty username with IP",
			input: "cache: rediss://:rediss_pass@192.168.1.100:6380/0",
			leak:  "rediss_pass",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := RedactSecrets(tc.input)
			if strings.Contains(result, tc.leak) {
				t.Errorf("credential leaked:\n  input:  %s\n  output: %s", tc.input, result)
			}
			if !strings.Contains(result, "[REDACTED]") {
				t.Errorf("expected [REDACTED] marker in output: %s", result)
			}
		})
	}
}

func TestRedactSecrets_EmailAddress(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"simple email", "contact: admin@example.com for details"},
		{"internal domain", "notify ops@monitoring.internal on failure"},
		{"subdomain", "cert owner is user@mail.corp.example.org"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := RedactSecrets(tc.input)
			if result == tc.input {
				t.Errorf("expected email to be redacted in %q, got: %s", tc.input, result)
			}
			if !strings.Contains(result, "[REDACTED]") {
				t.Errorf("expected [REDACTED] marker, got: %s", result)
			}
		})
	}
}

// TestRedactSecrets_EmailNoFalsePositive_IPv4 verifies that bare IPv4 addresses
// with a user prefix (e.g. "user@192.168.1.1") are NOT redacted. The email
// pattern requires a TLD consisting of two or more ASCII letters; a numeric
// final octet does not satisfy that requirement, so these should pass through.
func TestRedactSecrets_EmailNoFalsePositive_IPv4(t *testing.T) {
	cases := []string{
		"connect to user@192.168.1.1",
		"ssh nagios@10.0.0.1 failed",
	}
	for _, input := range cases {
		result := RedactSecrets(input)
		if result != input {
			t.Errorf("false positive: %q was redacted to %q", input, result)
		}
	}
}

// TestRedactSecrets_EmailNoFalsePositive_SystemdUnits verifies that systemd
// template unit instance names of the form "name@<uid>.service" are NOT
// redacted. The email regex previously matched these because the UID (e.g.
// "1000") satisfies [A-Za-z0-9.-]+ and "service" satisfies [A-Za-z]{2,}.
// These strings are critical diagnostic context: systemd logs frequently
// include lines such as "user@1000.service: Main process exited" or
// "Started polkitd@0.service", and redacting them strips the unit identity
// from the output that Claude uses for root-cause analysis.
func TestRedactSecrets_EmailNoFalsePositive_SystemdUnits(t *testing.T) {
	cases := []string{
		// Numeric UID instance — the most common form: systemd creates one
		// user@<uid>.service per logged-in user.
		"user@1000.service: Main process exited, code=exited, status=1/FAILURE",
		"Started user@1000.service - User Manager for UID 1000.",
		// Single-digit UID (system users such as polkitd use low UIDs).
		"polkitd@0.service loaded active running",
		// Multi-digit numeric instance in a log prefix.
		"systemd[1]: user@500.service: Deactivated successfully.",
	}
	for _, input := range cases {
		result := RedactSecrets(input)
		if result != input {
			t.Errorf("false positive: systemd unit name was redacted\n  input:  %s\n  output: %s", input, result)
		}
	}
}

// TestRedactSecrets_EmailStillRedactedAfterSystemdFix verifies that real email
// addresses continue to be redacted after the systemd false-positive fix.
// The updated regex still matches addresses whose domain section contains at
// least one letter, which covers all valid email hostnames.
func TestRedactSecrets_EmailStillRedactedAfterSystemdFix(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"simple address", "contact admin@example.com for support"},
		{"internal domain", "alert sent to ops@monitoring.internal"},
		{"subdomain address", "cert owner is user@mail.corp.example.org"},
		{"alphanumeric domain", "notify alert1@host2.example.com immediately"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := RedactSecrets(tc.input)
			if result == tc.input {
				t.Errorf("expected email to be redacted in %q, got unchanged output", tc.input)
			}
			if !strings.Contains(result, "[REDACTED]") {
				t.Errorf("expected [REDACTED] marker, got: %s", result)
			}
		})
	}
}

// TestRedactSecrets_JSONKeyValue verifies that JSON-formatted secrets with
// double-quoted keys and string values are redacted. The generic keyword=value
// pattern cannot match this form because the closing double quote after the
// key name breaks the \s*[=:] match, so a dedicated pattern is required.
func TestRedactSecrets_JSONKeyValue(t *testing.T) {
	cases := []struct {
		name  string
		input string
		leak  string
	}{
		{
			name:  "password value",
			input: `{"password": "s3cr3t123"}`,
			leak:  "s3cr3t123",
		},
		{
			name:  "token no spaces",
			input: `{"token":"api-token-xyz"}`,
			leak:  "api-token-xyz",
		},
		{
			name:  "secret in nested context",
			input: `error: {"code": 401, "secret": "hunter2", "msg": "unauthorized"}`,
			leak:  "hunter2",
		},
		{
			name:  "key with spaces around colon",
			input: `{"key" : "my-api-key-value"}`,
			leak:  "my-api-key-value",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := RedactSecrets(tc.input)
			if strings.Contains(result, tc.leak) {
				t.Errorf("secret leaked:\n  input:  %s\n  output: %s", tc.input, result)
			}
			if !strings.Contains(result, "[REDACTED]") {
				t.Errorf("expected [REDACTED] marker in output, got: %s", result)
			}
		})
	}
}

// TestRedactSecrets_JSONKeyValueNoFalsePositive verifies that JSON keys not in
// the sensitive keyword list are left untouched.
func TestRedactSecrets_JSONKeyValueNoFalsePositive(t *testing.T) {
	input := `{"status": "running", "count": "42", "host": "db.internal"}`
	result := RedactSecrets(input)
	if result != input {
		t.Errorf("false positive: %q was modified to %q", input, result)
	}
}

// TestRedactSecrets_StripeAPIKeys verifies that Stripe secret keys and
// restricted keys are redacted. Stripe uses underscore separators
// (sk_live_/sk_test_/rk_live_/rk_test_) rather than hyphens, so they are not
// caught by the sk- prefix pattern. They frequently appear in application logs
// when a Stripe API call fails, e.g. "invalid API key provided: sk_live_xxx".
func TestRedactSecrets_StripeAPIKeys(t *testing.T) {
	cases := []struct {
		name  string
		input string
		leak  string
	}{
		{
			name:  "live secret key inline",
			input: "Stripe error: invalid API key provided: sk_live_FAKE",
			leak:  "sk_live_FAKE",
		},
		{
			name:  "test secret key inline",
			input: "stripe charge failed with key sk_test_FAKE",
			leak:  "sk_test_FAKE",
		},
		{
			name:  "live restricted key",
			input: "authentication error for rk_live_FAKE",
			leak:  "rk_live_FAKE",
		},
		{
			name:  "test restricted key",
			input: "auth failed: rk_test_FAKE",
			leak:  "rk_test_FAKE",
		},
		{
			name:  "live key in env assignment",
			input: "STRIPE_SECRET_KEY=sk_live_FAKE",
			leak:  "sk_live_FAKE",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := RedactSecrets(tc.input)
			if strings.Contains(result, tc.leak) {
				t.Errorf("Stripe key leaked:\n  input:  %s\n  output: %s", tc.input, result)
			}
			if !strings.Contains(result, "[REDACTED]") {
				t.Errorf("expected [REDACTED] marker in output, got: %s", result)
			}
		})
	}
}

// TestRedactSecrets_GitHubAppTokens verifies that GitHub App token formats are
// redacted. The existing pattern covered classic PATs (ghp_) and OAuth tokens
// (gho_), but missed the three additional GitHub App token formats:
//   - ghs_ — server-to-server installation tokens issued by GitHub Apps,
//     commonly mounted as Kubernetes secrets and leaked into pod logs when an
//     API call fails (e.g. "invalid token ghs_XXXX").
//   - ghu_ — user-to-server tokens issued by GitHub Apps during OAuth flows.
//   - ghr_ — refresh tokens used to renew ghu_ tokens.
//
// All three appear in application error logs and would reach Claude's context
// unredacted without this fix.
func TestRedactSecrets_GitHubAppTokens(t *testing.T) {
	cases := []struct {
		name  string
		input string
		leak  string
	}{
		{
			name:  "ghs_ installation token inline",
			input: "GitHub App error: invalid token ghs_FAKEFAKEFAKEFAKEFAKEFAKEFAKE",
			leak:  "ghs_FAKEFAKEFAKEFAKEFAKEFAKEFAKE",
		},
		{
			name:  "ghs_ token in env assignment",
			input: "GITHUB_TOKEN=ghs_FAKEFAKEFAKEFAKEFAKEFAKEFAKE",
			leak:  "ghs_FAKEFAKEFAKEFAKEFAKEFAKEFAKE",
		},
		{
			name:  "ghu_ user-to-server token",
			input: "authentication failed for token ghu_FAKEFAKEFAKEFAKEFAKEFAKEFAKE",
			leak:  "ghu_FAKEFAKEFAKEFAKEFAKEFAKEFAKE",
		},
		{
			name:  "ghr_ refresh token",
			input: "token refresh error: ghr_FAKEFAKEFAKEFAKEFAKEFAKEFAKE expired",
			leak:  "ghr_FAKEFAKEFAKEFAKEFAKEFAKEFAKE",
		},
		{
			name:  "ghs_ token in log with surrounding context",
			input: `[2024-01-15] POST /repos/owner/repo/issues: 401 Unauthorized (token=ghs_FAKEFAKEFAKE)`,
			leak:  "ghs_FAKEFAKEFAKE",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := RedactSecrets(tc.input)
			if strings.Contains(result, tc.leak) {
				t.Errorf("GitHub App token leaked:\n  input:  %s\n  output: %s", tc.input, result)
			}
			if !strings.Contains(result, "[REDACTED]") {
				t.Errorf("expected [REDACTED] marker in output, got: %s", result)
			}
		})
	}
}

func TestRedactSecrets_NoFalsePositive(t *testing.T) {
	input := "CPU load is 4.5 at 12:00"
	result := RedactSecrets(input)
	if result != input {
		t.Errorf("false positive redaction: got %s", result)
	}
}

// TestRedactSecrets_NoFalsePositiveKeySuffix verifies that common English words
// ending in a keyword suffix (e.g. "monkey" ends in "key", "turkey" ends in
// "key") do not trigger false-positive redactions. Without a word-boundary
// guard, "monkey=bananas" would be partially redacted to "mon[REDACTED]",
// corrupting diagnostic output sent to Claude.
func TestRedactSecrets_NoFalsePositiveKeySuffix(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"monkey", "monkey=bananas"},
		{"donkey", "donkey=cart"},
		{"turkey", "turkey=dinner"},
		{"jockey", "jockey=horse"},
		{"hockey", "hockey=puck"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := RedactSecrets(tc.input)
			if result != tc.input {
				t.Errorf("false positive: %q was redacted to %q", tc.input, result)
			}
		})
	}
}

// TestRedactSecrets_UnderscorePrefixedKeywords verifies that underscore-prefixed
// keyword patterns (api_key, API_KEY, cache_token, etc.) are still redacted.
// Underscore is not a letter, so the word-boundary guard allows matches where
// the keyword is preceded by an underscore.
func TestRedactSecrets_UnderscorePrefixedKeywords(t *testing.T) {
	cases := []struct {
		name        string
		input       string
		mustNotHave string // substring that must NOT appear in the result
		mustHave    string // substring that MUST appear in the result
	}{
		{"api_key", "api_key=s3cr3t-value", "s3cr3t-value", "api_key="},
		{"API_KEY", "API_KEY=s3cr3t-value", "s3cr3t-value", "API_KEY="},
		{"cache_token", "cache_token=session-xyz", "session-xyz", "cache_token="},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := RedactSecrets(tc.input)
			if strings.Contains(result, tc.mustNotHave) {
				t.Errorf("%q: secret %q not redacted; got %q", tc.input, tc.mustNotHave, result)
			}
			if !strings.Contains(result, "[REDACTED]") {
				t.Errorf("%q: expected [REDACTED] in result, got %q", tc.input, result)
			}
			// Keyword name and separator must be preserved so the field identity is
			// visible in logs and alerts sent to Claude for root-cause analysis.
			if !strings.Contains(result, tc.mustHave) {
				t.Errorf("%q: expected keyword %q preserved in result, got %q", tc.input, tc.mustHave, result)
			}
		})
	}
}

func TestTruncate_Short(t *testing.T) {
	result := Truncate("short", 100)
	if result != "short" {
		t.Errorf("unexpected truncation: %s", result)
	}
}

func TestTruncate_Long(t *testing.T) {
	input := strings.Repeat("a", 200)
	result := Truncate(input, 100)
	if len(result) > 100 {
		t.Errorf("exceeds maxBytes: len=%d", len(result))
	}
	if !strings.Contains(result, "[truncated]") {
		t.Errorf("missing truncation marker")
	}
}

func TestTruncate_PreservesValidUTF8(t *testing.T) {
	// Place a 4-byte emoji right at the truncation boundary so a naive byte
	// slice would split the sequence and produce invalid UTF-8.
	emoji := "🔥" // 4 bytes: 0xF0 0x9F 0x94 0xA5
	// Build a string where the emoji starts at byte 98, so a cut at 100 bytes
	// lands inside the emoji.
	input := strings.Repeat("a", 98) + emoji + strings.Repeat("b", 50)
	result := Truncate(input, 100)
	if !utf8.ValidString(result) {
		t.Errorf("Truncate produced invalid UTF-8: %q", result)
	}
	if !strings.Contains(result, "[truncated]") {
		t.Errorf("missing truncation marker: %s", result)
	}
}

func TestTruncate_NeverExceedsMaxBytes(t *testing.T) {
	// truncationMarker is 16 bytes ("\n" + "... [truncated]"); ensure the total
	// output never exceeds maxBytes regardless of where the cut falls relative to
	// multi-byte characters. maxBytes=17 is the smallest value that allows any
	// content before the marker (cutAt = 17-16 = 1).
	for _, maxBytes := range []int{15, 16, 17, 50, 100, 4096} {
		input := strings.Repeat("x", maxBytes*2)
		result := Truncate(input, maxBytes)
		if len(result) > maxBytes {
			t.Errorf("maxBytes=%d: output len=%d exceeds limit", maxBytes, len(result))
		}
	}
}

func TestTruncate_ZeroMaxBytes(t *testing.T) {
	if got := Truncate("hello", 0); got != "" {
		t.Errorf("expected empty string for maxBytes=0, got %q", got)
	}
}

func TestTruncate_NegativeMaxBytes(t *testing.T) {
	if got := Truncate("hello", -1); got != "" {
		t.Errorf("expected empty string for maxBytes=-1, got %q", got)
	}
}

func TestTruncate_ExactBoundary(t *testing.T) {
	// Truncating exactly at a multi-byte boundary should keep the character.
	emoji := "🚀"                             // 4 bytes
	input := strings.Repeat("x", 96) + emoji // 100 bytes total
	result := Truncate(input, 100)
	// No truncation needed — string fits exactly.
	if result != input {
		t.Errorf("expected no truncation for exact-length string, got len=%d", len(result))
	}
}
