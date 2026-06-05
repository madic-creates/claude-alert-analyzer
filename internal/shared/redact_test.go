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

// TestRedactSecrets_BearerTokenInlineLogLine verifies that bearer and basic
// tokens appearing in log lines (without an "Authorization:" header prefix)
// are fully redacted by the inline bearer/basic pattern. Two gap cases that
// were missed by the previous character class [A-Za-z0-9+/=]:
//
//  1. JWT tokens: the old class excluded "." so the match stopped at the first
//     segment separator, leaving the payload (which may contain email, sub,
//     roles) and signature segments unredacted.
//
//  2. Hyphenated tokens: the old class excluded "-" so the match stopped at
//     the first hyphen — typically after just 2–3 characters — and the 20-char
//     minimum was never reached, leaving the entire token unredacted.
//
// The Authorization-header pattern (pattern 1) runs first and catches lines
// containing "Authorization: Bearer …"; the inline pattern tested here handles
// the remaining cases where the token appears in application log output.
func TestRedactSecrets_BearerTokenInlineLogLine(t *testing.T) {
	cases := []struct {
		name string
		// input must NOT contain "authorization:" so the Authorization-header
		// pattern does not fire first, ensuring only the inline bearer pattern is
		// exercised.
		input string
		leak  string // substring that must NOT remain in result
	}{
		{
			// JWT token (header.payload.signature) after "bearer" in a log line.
			// Previously only the header segment was redacted; the payload
			// segment containing base64url-encoded claims was left intact.
			name:  "JWT after bearer in log line",
			input: "authentication failed: bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IkZBS0UifQ.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIn0.FAKESIG",
			leak:  "eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIn0", // payload segment
		},
		{
			// Hyphenated bearer token in a log line.
			// Previously the match stopped at the first hyphen (only 2 chars
			// matched), so the 20-character minimum was never reached and the
			// entire token was left in the output unredacted.
			name:  "hyphenated bearer token in log line",
			input: "failed to call API: bearer my-service-api-token-abc123def456ghi789",
			leak:  "my-service-api-token-abc123def456ghi789",
		},
		{
			// Base64url token (underscore variant) after "bearer" in a log line.
			// base64url uses "_" instead of "/" and "-" instead of "+".
			// The input avoids "token:" before "bearer" so that the keyword=value
			// pattern does not consume "bearer" as a value first.
			name:  "base64url bearer token with underscores",
			input: "authentication error: bearer eyJhbGciOiJFUzI1NiIsImtpZCI6ImZha2UifQ_eyJzdWIiOiJ1c2VyXzEyMyJ9_FAKEsig_abc123def456",
			leak:  "eyJhbGciOiJFUzI1NiIsImtpZCI6ImZha2UifQ_eyJzdWIiOiJ1c2VyXzEyMyJ9_FAKEsig_abc123def456",
		},
		{
			// "basic" scheme with a hyphenated credential in a log line.
			name:  "basic scheme with hyphenated credential",
			input: "basic auth attempt: basic dXNlcjpwYXNz-with-extra-hyphen-padding12345",
			leak:  "dXNlcjpwYXNz-with-extra-hyphen-padding12345",
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

// TestRedactSecrets_JWTBareInLogLine verifies that JWT tokens appearing in log
// lines without a preceding "bearer" or "basic" keyword are still redacted.
// JWT payloads routinely contain PII (sub, email, roles) and must not reach the
// Claude API in clear text. The eyJ prefix (base64url of '{"') is a reliable
// fingerprint; requiring two dot separators avoids false positives on short
// base64url strings.
func TestRedactSecrets_JWTBareInLogLine(t *testing.T) {
	cases := []struct {
		name  string
		input string
		leak  string // substring that must NOT remain in result
	}{
		{
			// Full three-segment JWT after "token" keyword separated by a space
			// (not "token:" or "token="), so the keyword=value pattern does not fire.
			name:  "JWT after space-separated token keyword",
			input: "authentication failed: token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.FAKESIG",
			leak:  "eyJzdWIiOiJ1c2VyMTIzIn0", // payload with sub claim
		},
		{
			// JWT appearing bare with no keyword at all, e.g. copied from a log.
			name:  "bare JWT with no keyword prefix",
			input: "expired: eyJhbGciOiJSUzI1NiIsImtpZCI6ImZha2UifQ.eyJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20ifQ.FAKESIG2",
			leak:  "eyJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20ifQ", // payload with email claim
		},
		{
			// Unsigned JWT (alg=none): signature segment is empty, so the token
			// ends with a trailing dot. The pattern uses * (zero-or-more) for the
			// signature segment to handle this case.
			name:  "unsigned JWT with empty signature segment",
			input: "debug jwt: eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.",
			leak:  "eyJyb2xlIjoiYWRtaW4ifQ", // payload with admin role
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := RedactSecrets(tc.input)
			if strings.Contains(result, tc.leak) {
				t.Errorf("JWT payload leaked in output:\n  input:  %s\n  output: %s\n  leaked: %s", tc.input, result, tc.leak)
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

// TestRedactSecrets_AWSTempAccessKeyID verifies that STS-generated temporary
// access key IDs (ASIA prefix) are redacted. ASIA keys are issued by
// AssumeRole, GetFederationToken, and IRSA (IAM Roles for Service Accounts in
// Kubernetes) — they are equally sensitive as long-term AKIA keys and appear
// in application logs when AWS SDK calls fail with authentication errors.
func TestRedactSecrets_AWSTempAccessKeyID(t *testing.T) {
	input := "aws_access_key_id = ASIAIOSFODNN7EXAMPLE"
	result := RedactSecrets(input)
	if strings.Contains(result, "ASIAIOSFODNN7EXAMPLE") {
		t.Errorf("STS temporary access key ID not redacted: %s", result)
	}
}

func TestRedactSecrets_AWSTempKeyInText(t *testing.T) {
	input := "AssumeRole returned AccessKeyId: ASIAI44QH8DHBEXAMPLE"
	result := RedactSecrets(input)
	if strings.Contains(result, "ASIAI44QH8DHBEXAMPLE") {
		t.Errorf("STS temporary access key not redacted in free text: %s", result)
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

// TestRedactSecrets_SMTPAndLDAPURLs verifies that credential-bearing SMTP and
// LDAP URLs are fully redacted — both the username and the password — rather
// than receiving partial redaction via the email fallback pattern (which only
// catches password@host, leaving the username exposed).
func TestRedactSecrets_SMTPAndLDAPURLs(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		leakUser string
		leakPass string
	}{
		{
			name:     "smtp with username and password",
			input:    "EMAIL_URL=smtp://mailuser:secretpassword@smtp.example.com:587",
			leakUser: "mailuser",
			leakPass: "secretpassword",
		},
		{
			name:     "smtps with API key credential",
			input:    "SMTP_URL=smtps://apikey:SG.abcdefghijklmnop@smtp.sendgrid.net:465",
			leakUser: "apikey",
			leakPass: "SG.abcdefghijklmnop",
		},
		{
			name:     "ldap with bind DN username",
			input:    "LDAP_URL=ldap://cn=admin,dc=example,dc=com:bindpassword@ldap.example.com:389",
			leakUser: "cn=admin",
			leakPass: "bindpassword",
		},
		{
			name:     "ldaps with simple bind user",
			input:    "connecting ldaps://binduser:topsecret@ldap.internal:636 failed",
			leakUser: "binduser",
			leakPass: "topsecret",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := RedactSecrets(tc.input)
			if strings.Contains(result, tc.leakUser) {
				t.Errorf("username leaked:\n  input:  %s\n  output: %s", tc.input, result)
			}
			if strings.Contains(result, tc.leakPass) {
				t.Errorf("password leaked:\n  input:  %s\n  output: %s", tc.input, result)
			}
			if !strings.Contains(result, "[REDACTED]") {
				t.Errorf("expected [REDACTED] marker in output: %s", result)
			}
		})
	}
}

// TestRedactSecrets_NATSURLs verifies that credential-bearing NATS connection
// URLs are fully redacted. NATS is widely used in Kubernetes microservice
// architectures; authentication failures emit the full nats://user:pass@host URL.
func TestRedactSecrets_NATSURLs(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "standard NATS URL with credentials in error log",
			input: "failed to connect to nats://svcuser:s3cr3tpass@nats-cluster.internal:4222 Authorization violation",
			want:  "failed to connect to [REDACTED] Authorization violation",
		},
		{
			name:  "NATS URL in env assignment",
			input: "NATS_URL=nats://svcuser:s3cr3tpass@nats-cluster.internal:4222",
			want:  "NATS_URL=[REDACTED]",
		},
		{
			name:  "NATS URL without credentials is not redacted",
			input: "connecting to nats://nats-cluster.internal:4222",
			want:  "connecting to nats://nats-cluster.internal:4222",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactSecrets(tc.input)
			if got != tc.want {
				t.Errorf("RedactSecrets(%q)\n  got:  %s\n  want: %s", tc.input, got, tc.want)
			}
		})
	}
}

// TestRedactSecrets_SQLServerURLs verifies that credential-bearing Microsoft SQL
// Server connection URLs are fully redacted. Enterprise Kubernetes workloads
// frequently connect to SQL Server using go-mssqldb (sqlserver://) or older
// drivers (mssql://); authentication failures emit the full URL with credentials.
func TestRedactSecrets_SQLServerURLs(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "sqlserver:// URL with credentials in error log",
			input: "mssql: Login error: sqlserver://svcaccount:P%40ssw0rd@sql.prod.corp:1433?database=appdb",
			want:  "mssql: Login error: [REDACTED]",
		},
		{
			name:  "mssql:// URL with credentials in env assignment",
			input: "DATABASE_URL=mssql://svcaccount:P%40ssw0rd@sql.prod.corp:1433",
			want:  "DATABASE_URL=[REDACTED]",
		},
		{
			name:  "sqlserver URL without credentials is not redacted",
			input: "connecting to sqlserver://sql.prod.corp:1433",
			want:  "connecting to sqlserver://sql.prod.corp:1433",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactSecrets(tc.input)
			if got != tc.want {
				t.Errorf("RedactSecrets(%q)\n  got:  %s\n  want: %s", tc.input, got, tc.want)
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

// TestRedactSecrets_JSONCompoundKeyValue verifies that compound JSON key names
// commonly used in OAuth2 and cloud-provider API responses are redacted.
// The generic keyword=value pattern cannot catch these because the closing
// double-quote after the key name is not whitespace and therefore does not
// satisfy the \s*[=:] separator check. The JSON key-value pattern must include
// these compound names explicitly.
func TestRedactSecrets_JSONCompoundKeyValue(t *testing.T) {
	cases := []struct {
		name  string
		input string
		leak  string
		key   string // key name that must be preserved in output
	}{
		{
			name:  "access_token OAuth response",
			input: `{"access_token": "ya29.A0ARrdaM-FAKETOKEN"}`,
			leak:  "ya29.A0ARrdaM-FAKETOKEN",
			key:   "access_token",
		},
		{
			name:  "refresh_token in token response",
			input: `{"refresh_token": "1//0g-FAKEREFRESHTOKEN", "expires_in": 3600}`,
			leak:  "1//0g-FAKEREFRESHTOKEN",
			key:   "refresh_token",
		},
		{
			name:  "id_token JWT value",
			input: `{"id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IkZBS0UifQ.FAKE.FAKE"}`,
			leak:  "eyJhbGciOiJSUzI1NiIsImtpZCI6IkZBS0UifQ.FAKE.FAKE",
			key:   "id_token",
		},
		{
			name:  "api_key in error log",
			input: `{"error": "invalid_key", "api_key": "sk-proj-FAKEAPIKEY"}`,
			leak:  "sk-proj-FAKEAPIKEY",
			key:   "api_key",
		},
		{
			name:  "client_secret in OAuth client config",
			input: `{"client_id": "my-app", "client_secret": "FAKECLIENTSECRET123"}`,
			leak:  "FAKECLIENTSECRET123",
			key:   "client_secret",
		},
		{
			name:  "secret_key in AWS SDK error",
			input: `{"secret_key": "wJalrXUtnFEMI/K7MDENG/FAKE"}`,
			leak:  "wJalrXUtnFEMI/K7MDENG/FAKE",
			key:   "secret_key",
		},
		{
			name:  "private_key in service account JSON",
			input: `{"private_key": "-----BEGIN RSA PRIVATE KEY-----\nFAKEDATA\n-----END RSA PRIVATE KEY-----"}`,
			leak:  "FAKEDATA",
			key:   "private_key",
		},
		{
			name:  "signing_key in webhook config",
			input: `{"signing_key": "whsec_FAKESIGNINGKEY"}`,
			leak:  "whsec_FAKESIGNINGKEY",
			key:   "signing_key",
		},
		{
			name:  "auth_token in service response",
			input: `{"auth_token": "tok_FAKEAUTHTOKEN"}`,
			leak:  "tok_FAKEAUTHTOKEN",
			key:   "auth_token",
		},
		{
			name:  "access_key in cloud provider error",
			input: `{"access_key": "AKIAIOSFODNN7EXAMPLE"}`,
			leak:  "AKIAIOSFODNN7EXAMPLE",
			key:   "access_key",
		},
		{
			name:  "api_secret in HMAC config",
			input: `{"api_secret": "FAKEAPISECRET1234567890"}`,
			leak:  "FAKEAPISECRET1234567890",
			key:   "api_secret",
		},
		{
			name:  "access_token compact JSON no spaces",
			input: `{"access_token":"tok-FAKECOMPACT","token_type":"Bearer"}`,
			leak:  "tok-FAKECOMPACT",
			key:   "access_token",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := RedactSecrets(tc.input)
			if strings.Contains(result, tc.leak) {
				t.Errorf("compound JSON key %q: secret leaked:\n  input:  %s\n  output: %s", tc.key, tc.input, result)
			}
			if !strings.Contains(result, "[REDACTED]") {
				t.Errorf("compound JSON key %q: expected [REDACTED] marker in output, got: %s", tc.key, result)
			}
			// Key name must be preserved so operators can identify which field was redacted.
			if !strings.Contains(result, `"`+tc.key+`"`) {
				t.Errorf("compound JSON key %q: key name not preserved in output: %s", tc.key, result)
			}
		})
	}
}

// TestRedactSecrets_JSONCamelCaseKeyValue verifies that camelCase JSON key names
// commonly used in JavaScript/TypeScript APIs and OAuth2 client libraries are
// redacted. The JSON key-value pattern uses _? (optional underscore) so that
// accessToken, apiKey, clientSecret, etc. are matched in addition to their
// snake_case counterparts. The (?i) flag means PascalCase variants work too.
func TestRedactSecrets_JSONCamelCaseKeyValue(t *testing.T) {
	cases := []struct {
		name  string
		input string
		leak  string
		key   string // key name that must be preserved in output
	}{
		{
			name:  "accessToken OAuth response",
			input: `{"accessToken": "ya29.A0ARrdaM-FAKETOKEN"}`,
			leak:  "ya29.A0ARrdaM-FAKETOKEN",
			key:   "accessToken",
		},
		{
			name:  "refreshToken in token response",
			input: `{"refreshToken": "1//0g-FAKEREFRESHTOKEN", "expiresIn": 3600}`,
			leak:  "1//0g-FAKEREFRESHTOKEN",
			key:   "refreshToken",
		},
		{
			name:  "apiKey in error log",
			input: `{"error": "invalid_key", "apiKey": "sk-proj-FAKEAPIKEY"}`,
			leak:  "sk-proj-FAKEAPIKEY",
			key:   "apiKey",
		},
		{
			name:  "clientSecret in OAuth client config",
			input: `{"clientId": "my-app", "clientSecret": "FAKECLIENTSECRET123"}`,
			leak:  "FAKECLIENTSECRET123",
			key:   "clientSecret",
		},
		{
			name:  "privateKey in service account JSON",
			input: `{"privateKey": "-----BEGIN RSA PRIVATE KEY-----\nFAKEDATA\n-----END RSA PRIVATE KEY-----"}`,
			leak:  "FAKEDATA",
			key:   "privateKey",
		},
		{
			name:  "authToken in service response",
			input: `{"authToken": "tok_FAKEAUTHTOKEN"}`,
			leak:  "tok_FAKEAUTHTOKEN",
			key:   "authToken",
		},
		{
			name:  "secretKey in AWS SDK error",
			input: `{"secretKey": "wJalrXUtnFEMI/K7MDENG/FAKE"}`,
			leak:  "wJalrXUtnFEMI/K7MDENG/FAKE",
			key:   "secretKey",
		},
		{
			name:  "accessKey in cloud provider error",
			input: `{"accessKey": "AKIAIOSFODNN7EXAMPLE"}`,
			leak:  "AKIAIOSFODNN7EXAMPLE",
			key:   "accessKey",
		},
		{
			name:  "apiSecret compact JSON",
			input: `{"apiSecret":"FAKEAPISECRET1234567890"}`,
			leak:  "FAKEAPISECRET1234567890",
			key:   "apiSecret",
		},
		{
			name:  "PascalCase AccessToken",
			input: `{"AccessToken": "PascalFakeToken123"}`,
			leak:  "PascalFakeToken123",
			key:   "AccessToken",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := RedactSecrets(tc.input)
			if strings.Contains(result, tc.leak) {
				t.Errorf("camelCase JSON key %q: secret leaked:\n  input:  %s\n  output: %s", tc.key, tc.input, result)
			}
			if !strings.Contains(result, "[REDACTED]") {
				t.Errorf("camelCase JSON key %q: expected [REDACTED] marker in output, got: %s", tc.key, result)
			}
			if !strings.Contains(result, `"`+tc.key+`"`) {
				t.Errorf("camelCase JSON key %q: key name not preserved in output: %s", tc.key, result)
			}
		})
	}
}

// TestRedactSecrets_JSONCompoundKeyNoFalsePositive verifies that common
// non-sensitive JSON keys whose names contain sensitive substrings (e.g.
// "cache_key_count", "token_expiry") are NOT redacted.
func TestRedactSecrets_JSONCompoundKeyNoFalsePositive(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"cache_key_count is not a credential", `{"cache_key_count": "42"}`},
		{"token_expiry is not a credential", `{"token_expiry": "3600"}`},
		{"status is not a credential", `{"status": "running"}`},
		{"host is not a credential", `{"host": "db.internal"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := RedactSecrets(tc.input)
			if result != tc.input {
				t.Errorf("false positive: %q was modified to %q", tc.input, result)
			}
		})
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

// TestRedactSecrets_GitHubFineGrainedPAT verifies that GitHub fine-grained
// personal access tokens (github_pat_ prefix, introduced 2022) are redacted.
// These tokens appear in application error logs when GitHub API calls fail
// (e.g. "403 Forbidden: github_pat_xxx") and would reach Claude's context
// unredacted without the github_pat_ entry in the prefix pattern. The redact.go
// comment explicitly names github_pat_ as a token format requiring coverage;
// this test verifies the regex entry works end-to-end and will catch any
// accidental removal or corruption of that alternation.
func TestRedactSecrets_GitHubFineGrainedPAT(t *testing.T) {
	cases := []struct {
		name  string
		input string
		leak  string
	}{
		{
			name:  "token in authentication failure log",
			input: "authentication failed for github_pat_11ABCDEFG0xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			leak:  "github_pat_11ABCDEFG0xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		},
		{
			name:  "token in API error response",
			input: "GitHub API 403 Forbidden: github_pat_11FAKE000000000000000000000000000000000000000",
			leak:  "github_pat_11FAKE000000000000000000000000000000000000000",
		},
		{
			name:  "token in parenthesised log context",
			input: `[2024-01-15] POST /repos/owner/repo/issues: 403 (token=github_pat_11FAKEFAKE)`,
			leak:  "github_pat_11FAKEFAKE",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := RedactSecrets(tc.input)
			if strings.Contains(result, tc.leak) {
				t.Errorf("GitHub fine-grained PAT leaked:\n  input:  %s\n  output: %s", tc.input, result)
			}
			if !strings.Contains(result, "[REDACTED]") {
				t.Errorf("expected [REDACTED] marker in output, got: %s", result)
			}
		})
	}
}

// TestRedactSecrets_SlackTokens verifies that all Slack token prefix variants
// are redacted. xoxb- (bot), xoxp- (user/legacy), xoxa- (app-level), and
// xoxs- (workspace) were covered by the original xox[bpas]- pattern.
// xoxe- (Enterprise Grid) and xoxr- (refresh) were missing and would leak
// into Claude's context when Slack API calls failed and logged the token.
func TestRedactSecrets_SlackTokens(t *testing.T) {
	cases := []struct {
		name  string
		input string
		leak  string
	}{
		{
			name:  "xoxb bot token",
			input: "Slack error: invalid token xoxb-FAKETESTTOKEN",
			leak:  "xoxb-FAKETESTTOKEN",
		},
		{
			name:  "xoxp user token",
			input: "auth failed for xoxp-FAKETESTTOKEN",
			leak:  "xoxp-FAKETESTTOKEN",
		},
		{
			name:  "xoxa app-level token",
			input: "SLACK_TOKEN=xoxa-FAKETESTTOKEN",
			leak:  "xoxa-FAKETESTTOKEN",
		},
		{
			name:  "xoxs workspace token",
			input: "workspace token xoxs-FAKETESTTOKEN expired",
			leak:  "xoxs-FAKETESTTOKEN",
		},
		{
			name:  "xoxe Enterprise Grid token",
			input: "Enterprise Grid auth error: token=xoxe-FAKETESTTOKEN",
			leak:  "xoxe-FAKETESTTOKEN",
		},
		{
			name:  "xoxr refresh token",
			input: "token refresh failed: xoxr-FAKETESTTOKEN is invalid",
			leak:  "xoxr-FAKETESTTOKEN",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := RedactSecrets(tc.input)
			if strings.Contains(result, tc.leak) {
				t.Errorf("Slack token leaked:\n  input:  %s\n  output: %s", tc.input, result)
			}
			if !strings.Contains(result, "[REDACTED]") {
				t.Errorf("expected [REDACTED] marker in output, got: %s", result)
			}
		})
	}
}

// TestRedactSecrets_VaultTokens verifies that HashiCorp Vault service tokens
// (hvs. prefix) and batch tokens (hvb. prefix) are redacted. These tokens
// appear in application logs when a Vault API call fails with a 403 permission
// denied error, or when the Vault Agent Injector sidecar logs authentication
// failures. Without this pattern, a bare hvs.XXXX token in a Kubernetes pod
// log or CheckMK plugin output would reach Claude's context unredacted unless
// it happened to follow a keyword like "token=" that triggers the generic
// keyword=value pattern.
func TestRedactSecrets_VaultTokens(t *testing.T) {
	cases := []struct {
		name  string
		input string
		leak  string
	}{
		{
			name:  "service token in permission denied error",
			input: "vault: permission denied (token=hvs.CAESIFakeServiceTokenAbcDef1234)",
			leak:  "hvs.CAESIFakeServiceTokenAbcDef1234",
		},
		{
			name:  "service token as standalone value",
			input: "authenticating with hvs.CAESIFakeServiceToken",
			leak:  "hvs.CAESIFakeServiceToken",
		},
		{
			name:  "service token in env assignment",
			input: "VAULT_TOKEN=hvs.CAESIFakeServiceTokenAbcDef",
			leak:  "hvs.CAESIFakeServiceTokenAbcDef",
		},
		{
			name:  "batch token inline",
			input: "vault agent: token renewal failed for hvb.AAAAAQICAHiFakeToken",
			leak:  "hvb.AAAAAQICAHiFakeToken",
		},
		{
			name:  "batch token in env assignment",
			input: "VAULT_TOKEN=hvb.AAAAAQICAHiBatchFakeToken",
			leak:  "hvb.AAAAAQICAHiBatchFakeToken",
		},
		{
			name:  "service token in JSON error response",
			input: `{"errors":["permission denied"],"token":"hvs.CAESIFakeJsonToken"}`,
			leak:  "hvs.CAESIFakeJsonToken",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := RedactSecrets(tc.input)
			if strings.Contains(result, tc.leak) {
				t.Errorf("Vault token leaked:\n  input:  %s\n  output: %s", tc.input, result)
			}
			if !strings.Contains(result, "[REDACTED]") {
				t.Errorf("expected [REDACTED] marker in output, got: %s", result)
			}
		})
	}
}

// TestRedactSecrets_GitLabTokens verifies that all GitLab token prefix variants
// are redacted. These tokens surface in Kubernetes pod logs when CI/CD pipeline
// credentials or image-pull secrets are rejected by the GitLab API or registry
// (e.g. "UNAUTHORIZED: token glpat-xxx is invalid"). Without redaction they
// reach Claude's context in plain text.
//
// Token values are built from two separate string literals so that static secret
// scanners do not flag the test source as containing real credentials.
func TestRedactSecrets_GitLabTokens(t *testing.T) {
	// Each fake token is constructed by concatenating a prefix constant with a
	// suffix so that no complete token literal appears in the source.
	patTok := "glpat-" + "TestTokenAbcDef1"
	rrtTok := "glrrt-" + "TestTokenAbcDef2"
	rtTok := "glrt-" + "TestTokenAbcDef3"
	dtTok := "gldt-" + "TestTokenAbcDef4"
	soatTok := "glsoat-" + "TestTokenAbcDef5"
	agentTok := "glagent-" + "TestTokenAbcDef6"

	cases := []struct {
		name  string
		input string
		leak  string
	}{
		{
			name:  "personal access token in auth error",
			input: "UNAUTHORIZED: GitLab: token " + patTok + " is invalid or has expired",
			leak:  patTok,
		},
		{
			name:  "personal access token in env assignment",
			input: "CI_JOB_TOKEN=" + patTok,
			leak:  patTok,
		},
		{
			name:  "runner registration token in log",
			input: "runner registration failed: token=" + rrtTok,
			leak:  rrtTok,
		},
		{
			name:  "runner authentication token standalone",
			input: "authenticating runner with " + rtTok,
			leak:  rtTok,
		},
		{
			name:  "deploy token in image pull error",
			input: "imagePullError: unauthorized: deploy token " + dtTok + " rejected",
			leak:  dtTok,
		},
		{
			name:  "service account token in JSON error",
			input: `{"error":"forbidden","token":"` + soatTok + `"}`,
			leak:  soatTok,
		},
		{
			name:  "agent token in connection log",
			input: "gitlab-agent: connection failed, token=" + agentTok,
			leak:  agentTok,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := RedactSecrets(tc.input)
			if strings.Contains(result, tc.leak) {
				t.Errorf("GitLab token leaked:\n  input:  %s\n  output: %s", tc.input, result)
			}
			if !strings.Contains(result, "[REDACTED]") {
				t.Errorf("expected [REDACTED] marker in output, got: %s", result)
			}
		})
	}
}

// TestRedactSecrets_DockerHubPAT verifies that Docker Hub personal access
// tokens (dckr_pat_ prefix) are redacted. These tokens appear in Kubernetes
// imagePullErrors when a Docker Hub PAT is rejected by the registry API
// (e.g. "unauthorized: incorrect username or password … token=dckr_pat_xxx").
// Without redaction the token reaches Claude's context unredacted.
//
// Token values are built from two separate string literals so that static secret
// scanners do not flag the test source as containing real credentials.
func TestRedactSecrets_DockerHubPAT(t *testing.T) {
	tok1 := "dckr_pat_" + "TestDockerPat1"
	tok2 := "dckr_pat_" + "TestDockerPat2"
	cases := []struct {
		name  string
		input string
		leak  string
	}{
		{
			name:  "PAT in image pull error",
			input: "unauthorized: incorrect username or password — token " + tok1,
			leak:  tok1,
		},
		{
			name:  "PAT in env assignment",
			input: "DOCKER_TOKEN=" + tok2,
			leak:  tok2,
		},
		{
			name:  "PAT in JSON credentials field",
			input: `{"auths":{"registry-1.docker.io":{"auth":"` + tok1 + `"}}}`,
			leak:  tok1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := RedactSecrets(tc.input)
			if strings.Contains(result, tc.leak) {
				t.Errorf("Docker Hub PAT leaked:\n  input:  %s\n  output: %s", tc.input, result)
			}
			if !strings.Contains(result, "[REDACTED]") {
				t.Errorf("expected [REDACTED] marker in output, got: %s", result)
			}
		})
	}
}

// TestRedactSecrets_SendGridTokens verifies that SendGrid API keys (SG. prefix)
// are redacted when they appear bare in application pod logs. SendGrid keys use
// a two-part dot-separated base64url format (SG.<part1>.<part2>) and appear in
// logs when email delivery fails and the SendGrid API rejects the key. The
// keyword=value pattern catches keys in env-var assignments (SENDGRID_API_KEY=…)
// but not standalone occurrences without a keyword prefix; this vendor-prefix
// pattern closes that gap.
//
// Token values are built from separate string literals so that static secret
// scanners do not flag the test source as containing real credentials.
func TestRedactSecrets_SendGridTokens(t *testing.T) {
	// Build a representative two-part SendGrid API key from separate literals.
	sgKey := "SG." + "TestSgApiKeyPart1ABCDE123" + "." + "TestSgApiKeyPart2XYZ789FghIjkLmnOpqRstUvwXyz"

	cases := []struct {
		name  string
		input string
		leak  string
	}{
		{
			name:  "bare key in email delivery error log",
			input: "SendGrid API error: 403 Forbidden for key " + sgKey,
			leak:  sgKey,
		},
		{
			name:  "key in Django SMTP error",
			input: "django.core.mail: SMTPAuthenticationError — token " + sgKey + " rejected",
			leak:  sgKey,
		},
		{
			name:  "key in JSON error response",
			input: `{"errors":[{"message":"The provided authorization grant is invalid"}],"id":"` + sgKey + `"}`,
			leak:  sgKey,
		},
		{
			name:  "key in env assignment caught by vendor prefix",
			input: "SENDGRID_API_KEY=" + sgKey,
			leak:  sgKey,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := RedactSecrets(tc.input)
			if strings.Contains(result, tc.leak) {
				t.Errorf("SendGrid API key leaked:\n  input:  %s\n  output: %s", tc.input, result)
			}
			if !strings.Contains(result, "[REDACTED]") {
				t.Errorf("expected [REDACTED] marker in output, got: %s", result)
			}
		})
	}
}

// TestRedactSecrets_NpmTokens verifies that npm access tokens (npm_ prefix)
// are redacted when they appear in Node.js pod logs and CI/CD pipeline logs.
// npm tokens are 36-char alphanumeric strings with a distinctive npm_ prefix;
// they appear on registry authentication failures (e.g. "npm ERR! E401 … token
// npm_xxx is invalid") and in build-error traces that print an .npmrc file
// containing an embedded token. The keyword=value pattern catches tokens in
// explicit assignments (NPM_TOKEN=…) but not bare inline occurrences; this
// vendor-prefix pattern closes that gap.
//
// Token values are built from separate string literals so that static secret
// scanners do not flag the test source as containing real credentials.
func TestRedactSecrets_NpmTokens(t *testing.T) {
	tok1 := "npm_" + "TestNpmAccessToken123456789012345678"
	tok2 := "npm_" + "AnotherNpmToken0987654321abcdefghij"

	cases := []struct {
		name  string
		input string
		leak  string
	}{
		{
			name:  "token in npm registry auth error",
			input: "npm ERR! code E401\nnpm ERR! 401 Unauthorized - GET https://registry.npmjs.org — token " + tok1 + " is invalid",
			leak:  tok1,
		},
		{
			name:  "token in .npmrc trace",
			input: "//registry.npmjs.org/:_authToken=" + tok2,
			leak:  tok2,
		},
		{
			name:  "token in env assignment",
			input: "NPM_TOKEN=" + tok1,
			leak:  tok1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := RedactSecrets(tc.input)
			if strings.Contains(result, tc.leak) {
				t.Errorf("npm token leaked:\n  input:  %s\n  output: %s", tc.input, result)
			}
			if !strings.Contains(result, "[REDACTED]") {
				t.Errorf("expected [REDACTED] marker in output, got: %s", result)
			}
		})
	}
}

// TestRedactSecrets_HuggingFaceTokens verifies that HuggingFace access tokens
// (hf_ prefix) are redacted. Real tokens are ~36 alphanumeric characters.
// Split literals prevent the test file itself from containing a plain token.
func TestRedactSecrets_HuggingFaceTokens(t *testing.T) {
	tok1 := "hf_" + "QNTkBAbJbQSwZtFkIbXkVJoVTgUBRMNlIC"
	tok2 := "hf_" + "XtRzMnOpQrStuVwXyZaBcDeFgHiJkLmNoP"

	cases := []struct {
		name  string
		input string
		leak  string
	}{
		{
			name:  "bare token in auth failure log",
			input: "authentication failed for token " + tok1,
			leak:  tok1,
		},
		{
			name:  "token in env assignment",
			input: "HF_TOKEN=" + tok2,
			leak:  tok2,
		},
		{
			name:  "token in Python traceback",
			input: "huggingface_hub.utils._headers.LocalTokenNotFoundError: Token " + tok1 + " not valid",
			leak:  tok1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := RedactSecrets(tc.input)
			if strings.Contains(result, tc.leak) {
				t.Errorf("HuggingFace token leaked:\n  input:  %s\n  output: %s", tc.input, result)
			}
			if !strings.Contains(result, "[REDACTED]") {
				t.Errorf("expected [REDACTED] marker in output, got: %s", result)
			}
		})
	}
}

// TestRedactSecrets_DatabricksTokens verifies that Databricks personal access
// tokens (dapi prefix) are redacted. Real tokens are ~32 hex characters.
// Split literals prevent the test file itself from containing a plain token.
func TestRedactSecrets_DatabricksTokens(t *testing.T) {
	tok1 := "dapi" + "3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b"
	tok2 := "dapi" + "a1b2c3d4e5f60718293a4b5c6d7e8f90"

	cases := []struct {
		name  string
		input string
		leak  string
	}{
		{
			name:  "bare token in SDK auth failure log",
			input: "databricks.sdk: authentication failed with token " + tok1,
			leak:  tok1,
		},
		{
			name:  "token in env assignment",
			input: "DATABRICKS_TOKEN=" + tok2,
			leak:  tok2,
		},
		{
			name:  "token in REST API error log",
			input: "Error: 403 Forbidden, token=" + tok1 + " is invalid",
			leak:  tok1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := RedactSecrets(tc.input)
			if strings.Contains(result, tc.leak) {
				t.Errorf("Databricks token leaked:\n  input:  %s\n  output: %s", tc.input, result)
			}
			if !strings.Contains(result, "[REDACTED]") {
				t.Errorf("expected [REDACTED] marker in output, got: %s", result)
			}
		})
	}
}

// TestRedactSecrets_DigitalOceanTokens verifies that DigitalOcean personal
// access tokens (dop_v1_ prefix) are redacted. Real tokens are dop_v1_ followed
// by 64 hex characters; they appear in DOKS pod logs when DOCR auth fails.
// Split literals prevent the test file itself from containing a plain token.
func TestRedactSecrets_DigitalOceanTokens(t *testing.T) {
	tok1 := "dop_v1_" + "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
	tok2 := "dop_v1_" + "0f1e2d3c4b5a6978675645342312019f8e7d6c5b4a3928170605040302010009"

	cases := []struct {
		name  string
		input string
		leak  string
	}{
		{
			name:  "bare token in registry auth failure log",
			input: "failed to authenticate with registry: token " + tok1 + " is invalid",
			leak:  tok1,
		},
		{
			name:  "token in env assignment",
			input: "DIGITALOCEAN_TOKEN=" + tok2,
			leak:  tok2,
		},
		{
			name:  "token in Flux controller error log",
			input: "flux: DigitalOcean API error: authentication failed token=" + tok1,
			leak:  tok1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := RedactSecrets(tc.input)
			if strings.Contains(result, tc.leak) {
				t.Errorf("DigitalOcean token leaked:\n  input:  %s\n  output: %s", tc.input, result)
			}
			if !strings.Contains(result, "[REDACTED]") {
				t.Errorf("expected [REDACTED] marker in output, got: %s", result)
			}
		})
	}
}

// TestRedactSecrets_HTTPSCredentialURLs verifies that credential-bearing
// HTTP/HTTPS URLs are fully redacted. Go's net/http library includes the full
// URL in transport-layer error messages; the username portion would otherwise
// survive the email-pattern fallback which only redacts the password component.
func TestRedactSecrets_HTTPSCredentialURLs(t *testing.T) {
	cases := []struct {
		name  string
		input string
		leak  string
	}{
		{
			name:  "net/http dial error with HTTPS credentials",
			input: `dial tcp: lookup https://svcacct:hunter2@monitoring.corp.example.com: no such host`,
			leak:  "hunter2",
		},
		{
			name:  "username also not exposed via net/http error",
			input: `dial tcp: lookup https://svcacct:hunter2@monitoring.corp.example.com: no such host`,
			leak:  "svcacct",
		},
		{
			name:  "HTTP URL in env assignment",
			input: "WEBHOOK_URL=http://admin:topsecret@internal.alertmanager.corp:9093/hooks/alert",
			leak:  "topsecret",
		},
		{
			name:  "HTTPS URL without credentials is not redacted",
			input: "connecting to https://api.example.com/v1/alerts",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := RedactSecrets(tc.input)
			if tc.leak != "" {
				if strings.Contains(result, tc.leak) {
					t.Errorf("HTTP/HTTPS credential leaked:\n  input:  %s\n  output: %s", tc.input, result)
				}
				if !strings.Contains(result, "[REDACTED]") {
					t.Errorf("expected [REDACTED] marker in output, got: %s", result)
				}
			} else {
				if result != tc.input {
					t.Errorf("false positive: %q was unexpectedly changed to %q", tc.input, result)
				}
			}
		})
	}
}

// TestRedactSecrets_ClickHouseURLs verifies that credential-bearing ClickHouse
// connection URLs are redacted. The ClickHouse Go driver v2 uses
// clickhouse://user:password@host:9000/database for the native TCP protocol.
// Authentication failures log the full URL, exposing credentials in pod logs.
func TestRedactSecrets_ClickHouseURLs(t *testing.T) {
	cases := []struct {
		name  string
		input string
		leak  string
	}{
		{
			name:  "ClickHouse auth failure in error log",
			input: `exception: Code: 516. DB::Exception: clickhouse://svcuser:s3cr3t@clickhouse:9000/ops: Authentication failed: password is incorrect`,
			leak:  "s3cr3t",
		},
		{
			name:  "ClickHouse URL in env assignment",
			input: "CLICKHOUSE_URL=clickhouse://admin:hunter2@analytics.internal:9000/metrics",
			leak:  "hunter2",
		},
		{
			name:  "ClickHouse URL without credentials is not redacted",
			input: "connecting to clickhouse://clickhouse:9000/default",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := RedactSecrets(tc.input)
			if tc.leak != "" {
				if strings.Contains(result, tc.leak) {
					t.Errorf("ClickHouse credential leaked:\n  input:  %s\n  output: %s", tc.input, result)
				}
				if !strings.Contains(result, "[REDACTED]") {
					t.Errorf("expected [REDACTED] marker in output, got: %s", result)
				}
			} else {
				if result != tc.input {
					t.Errorf("false positive: %q was unexpectedly changed to %q", tc.input, result)
				}
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

// TestSanitizeAlertField verifies that SanitizeAlertField strips ALL control
// characters (including newlines and tabs) and trims surrounding whitespace.
// Alert fields are single-line identifiers; embedded newlines could inject fake
// Markdown headings into the Claude prompt (prompt injection). This differs from
// SanitizeOutput which preserves newlines and tabs for multi-line output.
func TestSanitizeAlertField(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"plain text unchanged", "CrashLoopBackOff", "CrashLoopBackOff"},
		{"leading and trailing whitespace trimmed", "  warning  ", "warning"},
		{"newline stripped", "foo\nbar", "foobar"},
		{"tab stripped", "foo\tbar", "foobar"},
		{"carriage return stripped", "foo\rbar", "foobar"},
		{"null byte stripped", "foo\x00bar", "foobar"},
		{"ESC stripped", "foo\x1bbar", "foobar"},
		{"C1 control stripped", "foo\u0080bar", "foobar"},
		{"DEL stripped", "foo\x7fbar", "foobar"},
		// Newline injection would add a fake Markdown heading to the Claude prompt
		// (e.g. "alertname\n## Injected Section\n..."); stripping the newline
		// collapses it to a single line so the heading syntax never takes effect.
		{"embedded newline prompt injection", "## Fake Section\nInjected content", "## Fake SectionInjected content"},
		// U+2028 and U+2029 are not covered by unicode.IsControl but are treated as
		// line breaks by ECMAScript and some renderers — same prompt-injection vector.
		{"U+2028 line separator stripped", "foo\u2028bar", "foobar"},
		{"U+2029 paragraph separator stripped", "foo\u2029bar", "foobar"},
		{"empty string", "", ""},
		{"only whitespace", "   ", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SanitizeAlertField(tc.input)
			if got != tc.want {
				t.Errorf("SanitizeAlertField(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// TestSanitizeOutput verifies that SanitizeOutput strips C0/C1/DEL control
// characters while preserving newlines and tabs.
func TestSanitizeOutput(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"newline preserved", "line1\nline2", "line1\nline2"},
		{"tab preserved", "col1\tcol2", "col1\tcol2"},
		{"carriage return stripped", "foo\rbar", "foobar"},
		{"null byte stripped", "foo\x00bar", "foobar"},
		{"ESC stripped", "foo\x1bbar", "foobar"},
		{"C1 control stripped", "foo\u0080bar", "foobar"},
		{"DEL stripped", "foo\x7fbar", "foobar"},
		{"ANSI escape sequence: ESC stripped, rest preserved", "\x1b[31mred\x1b[0m", "[31mred[0m"},
		{"regular text unchanged", "hello world", "hello world"},
		{"empty string", "", ""},
		{"only newlines and tabs", "\n\t\n", "\n\t\n"},
		{"U+2028 line separator stripped", "foo\u2028bar", "foobar"},
		{"U+2029 paragraph separator stripped", "foo\u2029bar", "foobar"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SanitizeOutput(tc.input)
			if got != tc.want {
				t.Errorf("SanitizeOutput(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
