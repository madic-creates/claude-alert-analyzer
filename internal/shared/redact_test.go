package shared

import (
	"strings"
	"testing"
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
