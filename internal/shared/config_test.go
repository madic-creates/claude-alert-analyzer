package shared

import (
	"os"
	"testing"
	"time"
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

// TestParseIntEnv_BelowMin verifies that ParseIntEnv returns an error when the
// value is below the minimum bound. The existing TestParseIntEnv_OutOfRange only
// covers the v > max branch of the `v < min || v > max` condition; without this
// test, a mutation that changed `<` to `>` in `v < min` would go undetected.
// In production, ParseIntEnv("MAX_AGENT_ROUNDS", "10", 1, 50) must reject values
// like 0 and -1 to prevent RunToolLoop from receiving an invalid maxRounds.
func TestParseIntEnv_BelowMin(t *testing.T) {
	t.Setenv("TEST_INT", "-1")
	_, err := ParseIntEnv("TEST_INT", "10", 0, 100)
	if err == nil {
		t.Fatal("expected error for below-minimum value")
	}
}

func TestParseBoolEnv_Unset(t *testing.T) {
	os.Unsetenv("TEST_BOOL_MISSING")
	got, err := ParseBoolEnv("TEST_BOOL_MISSING", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != true {
		t.Errorf("got %v, want true (fallback)", got)
	}
}

func TestParseBoolEnv_True(t *testing.T) {
	t.Setenv("TEST_BOOL", "true")
	got, err := ParseBoolEnv("TEST_BOOL", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != true {
		t.Errorf("got %v, want true", got)
	}
}

func TestParseBoolEnv_False(t *testing.T) {
	t.Setenv("TEST_BOOL", "false")
	got, err := ParseBoolEnv("TEST_BOOL", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != false {
		t.Errorf("got %v, want false", got)
	}
}

func TestParseBoolEnv_Numeric(t *testing.T) {
	t.Setenv("TEST_BOOL", "1")
	got, err := ParseBoolEnv("TEST_BOOL", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != true {
		t.Errorf("got %v, want true (from \"1\")", got)
	}

	t.Setenv("TEST_BOOL", "0")
	got, err = ParseBoolEnv("TEST_BOOL", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != false {
		t.Errorf("got %v, want false (from \"0\")", got)
	}
}

// TestParseBoolEnv_Uppercase verifies the bug-fix case: "TRUE" was previously
// treated as the negative branch by `EnvOrDefault(...) == "true"` patterns,
// silently disabling features the operator intended to enable. The helper now
// uses strconv.ParseBool which accepts the standard upper/lowercase variants.
func TestParseBoolEnv_Uppercase(t *testing.T) {
	t.Setenv("TEST_BOOL", "TRUE")
	got, err := ParseBoolEnv("TEST_BOOL", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != true {
		t.Errorf("got %v, want true (from \"TRUE\")", got)
	}
}

func TestParseBoolEnv_Invalid(t *testing.T) {
	t.Setenv("TEST_BOOL", "yes")
	_, err := ParseBoolEnv("TEST_BOOL", false)
	if err == nil {
		t.Fatal("expected error for unrecognised value \"yes\"")
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

func TestParseDurationEnv(t *testing.T) {
	t.Setenv("HIST_TTL", "")
	if d, err := ParseDurationEnv("HIST_TTL", 6*time.Hour); err != nil || d != 6*time.Hour {
		t.Fatalf("empty: got %v, %v; want 6h, nil", d, err)
	}
	t.Setenv("HIST_TTL", "90m")
	if d, err := ParseDurationEnv("HIST_TTL", 6*time.Hour); err != nil || d != 90*time.Minute {
		t.Fatalf("90m: got %v, %v; want 90m, nil", d, err)
	}
	t.Setenv("HIST_TTL", "nonsense")
	if _, err := ParseDurationEnv("HIST_TTL", 6*time.Hour); err == nil {
		t.Fatal("nonsense: want error, got nil")
	}
}
