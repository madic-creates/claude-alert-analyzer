package shared

import (
	"os"
	"testing"
)

func TestEnvOrDefault_Set(t *testing.T) {
	t.Setenv("TEST_KEY", "custom")
	if got := EnvOrDefault("TEST_KEY", "fallback"); got != "custom" {
		t.Errorf("got %q, want %q", got, "custom")
	}
}

func TestEnvOrDefault_Unset(t *testing.T) {
	os.Unsetenv("TEST_KEY_MISSING")
	if got := EnvOrDefault("TEST_KEY_MISSING", "fallback"); got != "fallback" {
		t.Errorf("got %q, want %q", got, "fallback")
	}
}

func TestParseIntEnv_Valid(t *testing.T) {
	t.Setenv("TEST_INT", "42")
	got, err := ParseIntEnv("TEST_INT", "10", 0, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 42 {
		t.Errorf("got %d, want 42", got)
	}
}

func TestParseIntEnv_Default(t *testing.T) {
	os.Unsetenv("TEST_INT_MISSING")
	got, err := ParseIntEnv("TEST_INT_MISSING", "10", 0, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 10 {
		t.Errorf("got %d, want 10", got)
	}
}

func TestParseIntEnv_InvalidString(t *testing.T) {
	t.Setenv("TEST_INT", "abc")
	_, err := ParseIntEnv("TEST_INT", "10", 0, 100)
	if err == nil {
		t.Fatal("expected error for non-numeric value")
	}
}

func TestParseIntEnv_OutOfRange(t *testing.T) {
	t.Setenv("TEST_INT", "200")
	_, err := ParseIntEnv("TEST_INT", "10", 0, 100)
	if err == nil {
		t.Fatal("expected error for out-of-range value")
	}
}

func TestRequireEnv_Set(t *testing.T) {
	t.Setenv("TEST_REQ", "value")
	got, err := RequireEnv("TEST_REQ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "value" {
		t.Errorf("got %q, want %q", got, "value")
	}
}

func TestRequireEnv_Unset(t *testing.T) {
	os.Unsetenv("TEST_REQ_MISSING")
	_, err := RequireEnv("TEST_REQ_MISSING")
	if err == nil {
		t.Fatal("expected error for unset env var")
	}
}
