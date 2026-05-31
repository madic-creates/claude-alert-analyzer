package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// runMainWithEnv builds and runs the k8s-analyzer binary with the given env
// vars and returns its exit code + stderr.
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
	bin := dir + "/k8s-analyzer"
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	return bin
}

func TestMain_FailsWhenBothAuthVarsSet(t *testing.T) {
	exit, stderr := runMainWithEnv(t, map[string]string{
		"ANTHROPIC_API_KEY":    "x",
		"ANTHROPIC_AUTH_TOKEN": "y",
		"WEBHOOK_SECRET":       "secret",
	})
	if exit == 0 {
		t.Fatalf("expected non-zero exit when both auth vars are set; stderr=%s", stderr)
	}
	if !strings.Contains(stderr, "set exactly one") {
		t.Errorf("expected 'set exactly one' in stderr, got: %s", stderr)
	}
}

func TestMain_FailsWhenNeitherAuthVarSet(t *testing.T) {
	exit, stderr := runMainWithEnv(t, map[string]string{
		"WEBHOOK_SECRET": "secret",
	})
	if exit == 0 {
		t.Fatalf("expected non-zero exit when neither auth var is set; stderr=%s", stderr)
	}
	if !strings.Contains(stderr, "must be set") {
		t.Errorf("expected 'must be set' in stderr, got: %s", stderr)
	}
}

// TestMain_FailsWhenWebhookSecretMissing verifies that the binary exits with
// code 1 and logs an error mentioning WEBHOOK_SECRET when the env var is not
// set. WEBHOOK_SECRET is the bearer-token gate for all incoming Alertmanager
// webhooks; starting without it would silently accept any caller.
func TestMain_FailsWhenWebhookSecretMissing(t *testing.T) {
	exit, out := runMainWithEnv(t, map[string]string{
		"ANTHROPIC_API_KEY": "x",
		// WEBHOOK_SECRET intentionally omitted
	})
	if exit == 0 {
		t.Fatalf("expected non-zero exit when WEBHOOK_SECRET is missing; output=%s", out)
	}
	if !strings.Contains(out, "WEBHOOK_SECRET") {
		t.Errorf("expected 'WEBHOOK_SECRET' in output, got: %s", out)
	}
}

// minEnv returns the minimum set of env vars needed to pass loadConfig() and
// reach the storm/breaker duration validation in main().
func minEnv() map[string]string {
	return map[string]string{
		"WEBHOOK_SECRET":    "secret",
		"ANTHROPIC_API_KEY": "x",
	}
}

// TestMain_FailsWhenStormModeNotifyIntervalInvalid verifies that the binary
// exits and logs an error mentioning STORM_MODE_NOTIFY_INTERVAL when the env
// var is not a valid Go duration string. An unparseable value would otherwise
// cause main() to call os.Exit(1) before binding to any port, making the
// failure mode silent and hard to diagnose without this test.
func TestMain_FailsWhenStormModeNotifyIntervalInvalid(t *testing.T) {
	env := minEnv()
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
	env := minEnv()
	env["CIRCUIT_BREAKER_NOTIFY_INTERVAL"] = "notaduration"
	exit, out := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for invalid CIRCUIT_BREAKER_NOTIFY_INTERVAL; output=%s", out)
	}
	if !strings.Contains(out, "CIRCUIT_BREAKER_NOTIFY_INTERVAL") {
		t.Errorf("expected 'CIRCUIT_BREAKER_NOTIFY_INTERVAL' in output, got: %s", out)
	}
}

// TestMain_FailsWhenCircuitBreakerThresholdInvalid verifies that the binary
// exits and logs an error mentioning CIRCUIT_BREAKER_THRESHOLD when the value
// exceeds the valid range [0, 100]. The threshold is a failure-count window,
// not a percentage; values above 100 are almost certainly a misconfiguration.
func TestMain_FailsWhenCircuitBreakerThresholdInvalid(t *testing.T) {
	env := minEnv()
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
	env := minEnv()
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
	env := minEnv()
	env["CIRCUIT_BREAKER_MAX_PROBE_SECONDS"] = "0"
	exit, out := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for invalid CIRCUIT_BREAKER_MAX_PROBE_SECONDS; output=%s", out)
	}
	if !strings.Contains(out, "CIRCUIT_BREAKER_MAX_PROBE_SECONDS") {
		t.Errorf("expected 'CIRCUIT_BREAKER_MAX_PROBE_SECONDS' in output, got: %s", out)
	}
}

// TestMain_FailsWhenKubeAPITimeoutInvalid verifies that the binary exits and
// logs an error mentioning KUBE_API_TIMEOUT when the env var is not a valid Go
// duration string.
func TestMain_FailsWhenKubeAPITimeoutInvalid(t *testing.T) {
	env := minEnv()
	env["KUBE_API_TIMEOUT"] = "notaduration"
	exit, out := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for invalid KUBE_API_TIMEOUT; output=%s", out)
	}
	if !strings.Contains(out, "KUBE_API_TIMEOUT") {
		t.Errorf("expected 'KUBE_API_TIMEOUT' in output, got: %s", out)
	}
}

// TestMain_FailsWhenPromTimeoutInvalid verifies that the binary exits and logs
// an error mentioning PROM_TIMEOUT when the env var is not a valid Go duration
// string.
func TestMain_FailsWhenPromTimeoutInvalid(t *testing.T) {
	env := minEnv()
	env["PROM_TIMEOUT"] = "notaduration"
	exit, out := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for invalid PROM_TIMEOUT; output=%s", out)
	}
	if !strings.Contains(out, "PROM_TIMEOUT") {
		t.Errorf("expected 'PROM_TIMEOUT' in output, got: %s", out)
	}
}

// TestMain_FailsWhenCooldownSecondsInvalid verifies that the binary exits and
// logs an error mentioning COOLDOWN_SECONDS when the value is outside the valid
// range [0, 86400]. COOLDOWN_SECONDS is the very first env var parsed in
// loadConfig(), so no other env vars are required to reach this error.
func TestMain_FailsWhenCooldownSecondsInvalid(t *testing.T) {
	exit, out := runMainWithEnv(t, map[string]string{
		"COOLDOWN_SECONDS": "99999", // exceeds max 86400
	})
	if exit == 0 {
		t.Fatalf("expected non-zero exit for invalid COOLDOWN_SECONDS; output=%s", out)
	}
	if !strings.Contains(out, "COOLDOWN_SECONDS") {
		t.Errorf("expected 'COOLDOWN_SECONDS' in output, got: %s", out)
	}
}

// TestMain_FailsWhenMaxLogBytesInvalid verifies that the binary exits and logs
// an error mentioning MAX_LOG_BYTES when the value is outside the valid range
// [256, 1048576]. MAX_LOG_BYTES is parsed before WEBHOOK_SECRET in loadConfig(),
// so no other env vars are required to reach this error.
func TestMain_FailsWhenMaxLogBytesInvalid(t *testing.T) {
	exit, out := runMainWithEnv(t, map[string]string{
		"MAX_LOG_BYTES": "100", // below min 256
	})
	if exit == 0 {
		t.Fatalf("expected non-zero exit for invalid MAX_LOG_BYTES; output=%s", out)
	}
	if !strings.Contains(out, "MAX_LOG_BYTES") {
		t.Errorf("expected 'MAX_LOG_BYTES' in output, got: %s", out)
	}
}

// TestMain_FailsWhenSkipResolvedInvalid verifies that the binary exits and logs
// an error mentioning SKIP_RESOLVED when the env var is not a valid boolean.
// SKIP_RESOLVED is validated in loadConfig() before the auth check, so only
// WEBHOOK_SECRET needs to be provided — the binary never reaches
// rest.InClusterConfig() when this env var is malformed.
func TestMain_FailsWhenSkipResolvedInvalid(t *testing.T) {
	exit, out := runMainWithEnv(t, map[string]string{
		"WEBHOOK_SECRET": "secret",
		"SKIP_RESOLVED":  "notabool",
	})
	if exit == 0 {
		t.Fatalf("expected non-zero exit for invalid SKIP_RESOLVED; output=%s", out)
	}
	if !strings.Contains(out, "SKIP_RESOLVED") {
		t.Errorf("expected 'SKIP_RESOLVED' in output, got: %s", out)
	}
}
