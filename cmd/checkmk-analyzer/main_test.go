package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func runMainWithEnv(t *testing.T, env map[string]string) (int, string) {
	t.Helper()

	binary := buildBinary(t)
	cmd := exec.Command(binary)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	exit := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		} else {
			t.Fatalf("unexpected error type: %v", err)
		}
	}
	return exit, string(out)
}

func buildBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := dir + "/checkmk-analyzer"
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	return bin
}

func minEnv() map[string]string {
	return map[string]string{
		"WEBHOOK_SECRET":     "secret",
		"CHECKMK_API_USER":   "u",
		"CHECKMK_API_SECRET": "s",
	}
}

func TestMain_FailsWhenBothAuthVarsSet(t *testing.T) {
	env := minEnv()
	env["ANTHROPIC_API_KEY"] = "x"
	env["ANTHROPIC_AUTH_TOKEN"] = "y"
	exit, stderr := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit when both auth vars are set; stderr=%s", stderr)
	}
	if !strings.Contains(stderr, "set exactly one") {
		t.Errorf("expected 'set exactly one' in stderr, got: %s", stderr)
	}
}

func TestMain_FailsWhenNeitherAuthVarSet(t *testing.T) {
	exit, stderr := runMainWithEnv(t, minEnv())
	if exit == 0 {
		t.Fatalf("expected non-zero exit when neither auth var is set; stderr=%s", stderr)
	}
	if !strings.Contains(stderr, "must be set") {
		t.Errorf("expected 'must be set' in stderr, got: %s", stderr)
	}
}

// TestMain_FailsWhenWebhookSecretMissing verifies that the binary exits with
// code 1 and logs an error mentioning WEBHOOK_SECRET when the env var is not
// set. WEBHOOK_SECRET is the bearer-token gate for all incoming CheckMK
// notifications; starting without it would silently accept any caller.
func TestMain_FailsWhenWebhookSecretMissing(t *testing.T) {
	exit, out := runMainWithEnv(t, map[string]string{
		// WEBHOOK_SECRET intentionally omitted; validated before CHECKMK_API_*
	})
	if exit == 0 {
		t.Fatalf("expected non-zero exit when WEBHOOK_SECRET is missing; output=%s", out)
	}
	if !strings.Contains(out, "WEBHOOK_SECRET") {
		t.Errorf("expected 'WEBHOOK_SECRET' in output, got: %s", out)
	}
}

// TestMain_FailsWhenCheckmkAPIUserMissing verifies that the binary exits when
// CHECKMK_API_USER is not set. Without it, the CheckMK API client cannot
// authenticate and all context-gathering calls would fail at runtime.
func TestMain_FailsWhenCheckmkAPIUserMissing(t *testing.T) {
	exit, out := runMainWithEnv(t, map[string]string{
		"WEBHOOK_SECRET": "secret",
		// CHECKMK_API_USER intentionally omitted
	})
	if exit == 0 {
		t.Fatalf("expected non-zero exit when CHECKMK_API_USER is missing; output=%s", out)
	}
	if !strings.Contains(out, "CHECKMK_API_USER") {
		t.Errorf("expected 'CHECKMK_API_USER' in output, got: %s", out)
	}
}

// TestMain_FailsWhenCheckmkAPISecretMissing verifies that the binary exits when
// CHECKMK_API_SECRET is not set. Without it, the CheckMK REST API client
// cannot authenticate and all context-gathering calls would fail at runtime.
func TestMain_FailsWhenCheckmkAPISecretMissing(t *testing.T) {
	exit, out := runMainWithEnv(t, map[string]string{
		"WEBHOOK_SECRET":   "secret",
		"CHECKMK_API_USER": "user",
		// CHECKMK_API_SECRET intentionally omitted
	})
	if exit == 0 {
		t.Fatalf("expected non-zero exit when CHECKMK_API_SECRET is missing; output=%s", out)
	}
	if !strings.Contains(out, "CHECKMK_API_SECRET") {
		t.Errorf("expected 'CHECKMK_API_SECRET' in output, got: %s", out)
	}
}

// minEnvWithAuth returns the minimum env vars needed to pass loadConfig() and
// reach the storm/breaker duration validation in main(). ANTHROPIC_API_KEY is
// required to pass the auth check that runs inside loadConfig().
func minEnvWithAuth() map[string]string {
	env := minEnv()
	env["ANTHROPIC_API_KEY"] = "x"
	return env
}

// TestMain_FailsWhenCircuitBreakerThresholdInvalid verifies that the binary
// exits and logs an error mentioning CIRCUIT_BREAKER_THRESHOLD when the value
// exceeds the valid range [0, 100]. The threshold is a failure-count window,
// not a percentage; values above 100 are almost certainly a misconfiguration.
func TestMain_FailsWhenCircuitBreakerThresholdInvalid(t *testing.T) {
	env := minEnvWithAuth()
	env["CIRCUIT_BREAKER_THRESHOLD"] = "101"
	exit, out := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for invalid CIRCUIT_BREAKER_THRESHOLD; output=%s", out)
	}
	if !strings.Contains(out, "CIRCUIT_BREAKER_THRESHOLD") {
		t.Errorf("expected 'CIRCUIT_BREAKER_THRESHOLD' in output, got: %s", out)
	}
}

// TestMain_FailsWhenCircuitBreakerOpenSecondsInvalid verifies that the binary
// exits and logs an error mentioning CIRCUIT_BREAKER_OPEN_SECONDS when the
// value is outside the valid range [1, 3600]. An operator who sets this to 0
// expecting to disable the open-state duration gets a clear config error
// instead of a confusing runtime failure.
func TestMain_FailsWhenCircuitBreakerOpenSecondsInvalid(t *testing.T) {
	env := minEnvWithAuth()
	env["CIRCUIT_BREAKER_OPEN_SECONDS"] = "0"
	exit, out := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for invalid CIRCUIT_BREAKER_OPEN_SECONDS; output=%s", out)
	}
	if !strings.Contains(out, "CIRCUIT_BREAKER_OPEN_SECONDS") {
		t.Errorf("expected 'CIRCUIT_BREAKER_OPEN_SECONDS' in output, got: %s", out)
	}
}

// TestMain_FailsWhenCircuitBreakerMaxProbeSecondsInvalid verifies that the
// binary exits and logs an error mentioning CIRCUIT_BREAKER_MAX_PROBE_SECONDS
// when the value is outside the valid range [1, 3600].
func TestMain_FailsWhenCircuitBreakerMaxProbeSecondsInvalid(t *testing.T) {
	env := minEnvWithAuth()
	env["CIRCUIT_BREAKER_MAX_PROBE_SECONDS"] = "0"
	exit, out := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for invalid CIRCUIT_BREAKER_MAX_PROBE_SECONDS; output=%s", out)
	}
	if !strings.Contains(out, "CIRCUIT_BREAKER_MAX_PROBE_SECONDS") {
		t.Errorf("expected 'CIRCUIT_BREAKER_MAX_PROBE_SECONDS' in output, got: %s", out)
	}
}

// TestMain_FailsWhenStormModeNotifyIntervalInvalid verifies that the binary
// exits and logs an error mentioning STORM_MODE_NOTIFY_INTERVAL when the env
// var is not a valid Go duration string. An unparseable value would otherwise
// cause main() to call os.Exit(1) before binding to any port, making the
// failure mode silent and hard to diagnose without this test.
func TestMain_FailsWhenStormModeNotifyIntervalInvalid(t *testing.T) {
	env := minEnvWithAuth()
	env["STORM_MODE_NOTIFY_INTERVAL"] = "notaduration"
	exit, out := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for invalid STORM_MODE_NOTIFY_INTERVAL; output=%s", out)
	}
	if !strings.Contains(out, "STORM_MODE_NOTIFY_INTERVAL") {
		t.Errorf("expected 'STORM_MODE_NOTIFY_INTERVAL' in output, got: %s", out)
	}
}

// TestMain_FailsWhenCircuitBreakerNotifyIntervalInvalid verifies that the
// binary exits and logs an error mentioning CIRCUIT_BREAKER_NOTIFY_INTERVAL
// when the env var is not a valid Go duration string.
func TestMain_FailsWhenCircuitBreakerNotifyIntervalInvalid(t *testing.T) {
	env := minEnvWithAuth()
	env["CIRCUIT_BREAKER_NOTIFY_INTERVAL"] = "notaduration"
	exit, out := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for invalid CIRCUIT_BREAKER_NOTIFY_INTERVAL; output=%s", out)
	}
	if !strings.Contains(out, "CIRCUIT_BREAKER_NOTIFY_INTERVAL") {
		t.Errorf("expected 'CIRCUIT_BREAKER_NOTIFY_INTERVAL' in output, got: %s", out)
	}
}

// TestMain_FailsWhenHistoryTTLInvalid verifies that the binary exits and logs
// an error mentioning HISTORY_TTL when the env var is not a valid Go duration
// string. LoadHistoryConfig is called in main() after loadConfig() so the
// minimum valid startup env (with auth) must be provided.
func TestMain_FailsWhenHistoryTTLInvalid(t *testing.T) {
	env := minEnvWithAuth()
	env["HISTORY_TTL"] = "notaduration"
	exit, out := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for invalid HISTORY_TTL; output=%s", out)
	}
	if !strings.Contains(out, "HISTORY_TTL") {
		t.Errorf("expected 'HISTORY_TTL' in output, got: %s", out)
	}
}

// TestMain_FailsWhenCheckmkAPITimeoutInvalid verifies that the binary exits
// and logs an error mentioning CHECKMK_API_TIMEOUT when the env var is not a
// valid Go duration string. Mirrors TestMain_FailsWhenKubeAPITimeoutInvalid in
// cmd/k8s-analyzer.
func TestMain_FailsWhenCheckmkAPITimeoutInvalid(t *testing.T) {
	env := minEnvWithAuth()
	env["CHECKMK_API_TIMEOUT"] = "notaduration"
	exit, out := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for invalid CHECKMK_API_TIMEOUT; output=%s", out)
	}
	if !strings.Contains(out, "CHECKMK_API_TIMEOUT") {
		t.Errorf("expected 'CHECKMK_API_TIMEOUT' in output, got: %s", out)
	}
}
