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
}

func TestRedactSecrets_BearerToken(t *testing.T) {
	input := "Authorization: Bearer sk-ant-abc123def456ghi789jkl"
	result := RedactSecrets(input)
	if strings.Contains(result, "sk-ant-") {
		t.Errorf("bearer token not redacted: %s", result)
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
		name  string
		input string
		want  string // substring that must NOT appear in the result
	}{
		{"api_key", "api_key=s3cr3t-value", "s3cr3t-value"},
		{"API_KEY", "API_KEY=s3cr3t-value", "s3cr3t-value"},
		{"cache_token", "cache_token=session-xyz", "session-xyz"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := RedactSecrets(tc.input)
			if strings.Contains(result, tc.want) {
				t.Errorf("%q: secret %q not redacted; got %q", tc.input, tc.want, result)
			}
			if !strings.Contains(result, "[REDACTED]") {
				t.Errorf("%q: expected [REDACTED] in result, got %q", tc.input, result)
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
	emoji := "🚀" // 4 bytes
	input := strings.Repeat("x", 96) + emoji // 100 bytes total
	result := Truncate(input, 100)
	// No truncation needed — string fits exactly.
	if result != input {
		t.Errorf("expected no truncation for exact-length string, got len=%d", len(result))
	}
}
