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

func TestRedactSecrets_MongoDBURL(t *testing.T) {
	input := "uri: mongodb+srv://admin:p%40ss@cluster0.example.net/mydb"
	result := RedactSecrets(input)
	if strings.Contains(result, "p%40ss") {
		t.Errorf("mongodb credentials not redacted: %s", result)
	}
}

func TestRedactSecrets_NoFalsePositive(t *testing.T) {
	input := "CPU load is 4.5 at 12:00"
	result := RedactSecrets(input)
	if result != input {
		t.Errorf("false positive redaction: got %s", result)
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
	if len(result) > 120 {
		t.Errorf("not truncated: len=%d", len(result))
	}
	if !strings.Contains(result, "[truncated]") {
		t.Errorf("missing truncation marker")
	}
}

func TestTruncateLines_Short(t *testing.T) {
	input := "line1\nline2\nline3"
	result := TruncateLines(input, 5)
	if result != input {
		t.Errorf("unexpected truncation: %s", result)
	}
}

func TestTruncateLines_Long(t *testing.T) {
	input := "line1\nline2\nline3\nline4\nline5"
	result := TruncateLines(input, 2)
	if !strings.Contains(result, "line1") || !strings.Contains(result, "line2") {
		t.Errorf("expected first 2 lines: %s", result)
	}
	if strings.Contains(result, "line3") {
		t.Errorf("should not contain line3: %s", result)
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
