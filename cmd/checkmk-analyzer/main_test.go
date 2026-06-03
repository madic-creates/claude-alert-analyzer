package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
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

// TestMain_FailsWhenMaxAgentRoundsInvalid verifies that the binary exits and
// logs an error mentioning MAX_AGENT_ROUNDS when the value is outside the valid
// range [1, 50]. LoadPolicy is called in main() after loadConfig() so the
// minimum auth env (minEnvWithAuth) must be provided to reach this validation.
// MAX_AGENT_ROUNDS=0 is below the minimum (1 round = at least one tool loop);
// the binary must fail fast rather than silently skipping agentic analysis
// without operator awareness.
func TestMain_FailsWhenMaxAgentRoundsInvalid(t *testing.T) {
	env := minEnvWithAuth()
	env["MAX_AGENT_ROUNDS"] = "0" // below min 1
	exit, out := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for invalid MAX_AGENT_ROUNDS; output=%s", out)
	}
	if !strings.Contains(out, "MAX_AGENT_ROUNDS") {
		t.Errorf("expected 'MAX_AGENT_ROUNDS' in output, got: %s", out)
	}
}

// TestMain_FailsWhenGroupCooldownSecondsInvalid verifies that the binary exits
// and logs an error mentioning GROUP_COOLDOWN_SECONDS when the value exceeds
// the valid range [0, 86400]. GROUP_COOLDOWN_SECONDS is validated inside
// LoadPolicy, which is called after loadConfig(), so minEnvWithAuth() is needed.
func TestMain_FailsWhenGroupCooldownSecondsInvalid(t *testing.T) {
	env := minEnvWithAuth()
	env["GROUP_COOLDOWN_SECONDS"] = "86401" // exceeds max 86400
	exit, out := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for invalid GROUP_COOLDOWN_SECONDS; output=%s", out)
	}
	if !strings.Contains(out, "GROUP_COOLDOWN_SECONDS") {
		t.Errorf("expected 'GROUP_COOLDOWN_SECONDS' in output, got: %s", out)
	}
}

// TestMain_FailsWhenStormModeThresholdInvalid verifies that the binary exits
// and logs an error mentioning STORM_MODE_THRESHOLD when the value exceeds
// the valid range [0, 100000]. STORM_MODE_THRESHOLD is validated inside
// LoadPolicy, which is called after loadConfig(), so minEnvWithAuth() is needed.
func TestMain_FailsWhenStormModeThresholdInvalid(t *testing.T) {
	env := minEnvWithAuth()
	env["STORM_MODE_THRESHOLD"] = "100001" // exceeds max 100000
	exit, out := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for invalid STORM_MODE_THRESHOLD; output=%s", out)
	}
	if !strings.Contains(out, "STORM_MODE_THRESHOLD") {
		t.Errorf("expected 'STORM_MODE_THRESHOLD' in output, got: %s", out)
	}
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

// TestMain_FailsWhenStormModeNotifyIntervalNegative verifies that a negative
// STORM_MODE_NOTIFY_INTERVAL is rejected at startup. A negative duration is a
// valid Go duration string but LoadStormProtectionConfig rejects values <= 0.
// Mirrors TestMain_FailsWhenCheckmkAPITimeoutNegative for the notify-interval path.
func TestMain_FailsWhenStormModeNotifyIntervalNegative(t *testing.T) {
	env := minEnvWithAuth()
	env["STORM_MODE_NOTIFY_INTERVAL"] = "-1s"
	exit, out := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for negative STORM_MODE_NOTIFY_INTERVAL; output=%s", out)
	}
	if !strings.Contains(out, "STORM_MODE_NOTIFY_INTERVAL") {
		t.Errorf("expected 'STORM_MODE_NOTIFY_INTERVAL' in output, got: %s", out)
	}
}

// TestMain_FailsWhenCircuitBreakerNotifyIntervalNegative verifies that a
// negative CIRCUIT_BREAKER_NOTIFY_INTERVAL is rejected at startup. A negative
// duration is a valid Go duration string but LoadStormProtectionConfig rejects
// values <= 0.
func TestMain_FailsWhenCircuitBreakerNotifyIntervalNegative(t *testing.T) {
	env := minEnvWithAuth()
	env["CIRCUIT_BREAKER_NOTIFY_INTERVAL"] = "-30s"
	exit, out := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for negative CIRCUIT_BREAKER_NOTIFY_INTERVAL; output=%s", out)
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

// TestMain_FailsWhenCheckmkAPITimeoutNegative verifies that a negative
// CHECKMK_API_TIMEOUT is rejected at startup. A negative duration is a valid Go
// duration string but creates an already-expired context, causing all CheckMK
// API calls to fail immediately with context.DeadlineExceeded.
func TestMain_FailsWhenCheckmkAPITimeoutNegative(t *testing.T) {
	env := minEnvWithAuth()
	env["CHECKMK_API_TIMEOUT"] = "-1s"
	exit, out := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for negative CHECKMK_API_TIMEOUT; output=%s", out)
	}
	if !strings.Contains(out, "CHECKMK_API_TIMEOUT") {
		t.Errorf("expected 'CHECKMK_API_TIMEOUT' in output, got: %s", out)
	}
}

// TestMain_FailsWhenSSHEnabledInvalid verifies that the binary exits and logs
// an error mentioning SSH_ENABLED when the env var is not a valid boolean.
// SSH_ENABLED is validated after the auth check in loadConfig(), so the minimum
// auth env (minEnvWithAuth) must be provided to reach this validation point.
func TestMain_FailsWhenSSHEnabledInvalid(t *testing.T) {
	env := minEnvWithAuth()
	env["SSH_ENABLED"] = "notabool"
	exit, out := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for invalid SSH_ENABLED; output=%s", out)
	}
	if !strings.Contains(out, "SSH_ENABLED") {
		t.Errorf("expected 'SSH_ENABLED' in output, got: %s", out)
	}
}

// TestMain_FailsWhenHistoryEnabledInvalid verifies that the binary exits and
// logs an error mentioning HISTORY_ENABLED when the env var is not a valid
// boolean. LoadHistoryConfig is called in main() after loadConfig() so the
// minimum auth env (minEnvWithAuth) must be provided to reach this path.
func TestMain_FailsWhenHistoryEnabledInvalid(t *testing.T) {
	env := minEnvWithAuth()
	env["HISTORY_ENABLED"] = "notabool"
	exit, out := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for invalid HISTORY_ENABLED; output=%s", out)
	}
	if !strings.Contains(out, "HISTORY_ENABLED") {
		t.Errorf("expected 'HISTORY_ENABLED' in output, got: %s", out)
	}
}

// TestMain_FailsWhenHistoryMaxEntriesInvalid verifies that the binary exits and
// logs an error mentioning HISTORY_MAX_ENTRIES when the value is outside the
// valid range [1, 100]. Requires minEnvWithAuth to reach LoadHistoryConfig.
func TestMain_FailsWhenHistoryMaxEntriesInvalid(t *testing.T) {
	env := minEnvWithAuth()
	env["HISTORY_MAX_ENTRIES"] = "0" // below min 1
	exit, out := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for invalid HISTORY_MAX_ENTRIES; output=%s", out)
	}
	if !strings.Contains(out, "HISTORY_MAX_ENTRIES") {
		t.Errorf("expected 'HISTORY_MAX_ENTRIES' in output, got: %s", out)
	}
}

// TestMain_FailsWhenHistoryTTLNegative verifies that a negative HISTORY_TTL is
// rejected at startup. A negative duration is a valid Go duration string but
// LoadHistoryConfig explicitly rejects ttl <= 0. Mirrors
// TestMain_FailsWhenCheckmkAPITimeoutNegative.
func TestMain_FailsWhenHistoryTTLNegative(t *testing.T) {
	env := minEnvWithAuth()
	env["HISTORY_TTL"] = "-1h"
	exit, out := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for negative HISTORY_TTL; output=%s", out)
	}
	if !strings.Contains(out, "HISTORY_TTL") {
		t.Errorf("expected 'HISTORY_TTL' in output, got: %s", out)
	}
}

// TestMain_FailsWhenHistoryInjectPriorInvalid verifies that the binary exits
// and logs an error mentioning HISTORY_INJECT_PRIOR when the env var is not a
// valid boolean. Requires minEnvWithAuth to reach LoadHistoryConfig.
func TestMain_FailsWhenHistoryInjectPriorInvalid(t *testing.T) {
	env := minEnvWithAuth()
	env["HISTORY_INJECT_PRIOR"] = "notabool"
	exit, out := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for invalid HISTORY_INJECT_PRIOR; output=%s", out)
	}
	if !strings.Contains(out, "HISTORY_INJECT_PRIOR") {
		t.Errorf("expected 'HISTORY_INJECT_PRIOR' in output, got: %s", out)
	}
}

// setLoadConfigEnv sets every env var required by loadConfig so a sub-test
// can call loadConfig() directly without triggering os.Exit. Each var is
// registered via t.Setenv so the test harness restores the original value on
// completion, even when loadConfig() internally calls os.Unsetenv for the
// three Anthropic vars.
func setLoadConfigEnv(t *testing.T) {
	t.Helper()
	t.Setenv("WEBHOOK_SECRET", "test-secret")
	t.Setenv("CHECKMK_API_USER", "test-user")
	t.Setenv("CHECKMK_API_SECRET", "test-api-secret")
	t.Setenv("ANTHROPIC_API_KEY", "test-api-key")
	// Ensure ANTHROPIC_AUTH_TOKEN is unset so loadConfig does not reject
	// both auth vars being set. Pattern from stormProtectionUnsetAll: call
	// t.Setenv first (registers cleanup to restore the original value), then
	// os.Unsetenv so LookupEnv sees "not set" rather than "set to empty".
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "")
	os.Unsetenv("ANTHROPIC_AUTH_TOKEN")
}

// TestLoadConfig_AnthropicVarsUnsetAfterLoad verifies that loadConfig() clears
// ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN, and ANTHROPIC_BASE_URL from the
// process environment after reading them. main.go is the single source of
// truth for these values; removing them prevents the Claude SDK from later
// re-reading the process env and picking up stale or incorrect credentials.
// This also verifies that the values are preserved in the returned Config
// struct even though the env vars are gone.
func TestLoadConfig_AnthropicVarsUnsetAfterLoad(t *testing.T) {
	setLoadConfigEnv(t)
	t.Setenv("ANTHROPIC_BASE_URL", "https://test.example.com")

	cfg := loadConfig()

	// The returned config must carry the values that were set.
	if cfg.APIKey != "test-api-key" {
		t.Errorf("APIKey = %q, want %q", cfg.APIKey, "test-api-key")
	}
	if cfg.APIBaseURL != "https://test.example.com" {
		t.Errorf("APIBaseURL = %q, want %q", cfg.APIBaseURL, "https://test.example.com")
	}

	// The env vars must have been removed so the SDK cannot read them.
	if v, ok := os.LookupEnv("ANTHROPIC_API_KEY"); ok {
		t.Errorf("ANTHROPIC_API_KEY still in env after loadConfig: %q", v)
	}
	if v, ok := os.LookupEnv("ANTHROPIC_AUTH_TOKEN"); ok {
		t.Errorf("ANTHROPIC_AUTH_TOKEN still in env after loadConfig: %q", v)
	}
	if v, ok := os.LookupEnv("ANTHROPIC_BASE_URL"); ok {
		t.Errorf("ANTHROPIC_BASE_URL still in env after loadConfig: %q", v)
	}
}

// TestLoadConfig_AuthTokenPathPreservesToken verifies that ANTHROPIC_AUTH_TOKEN
// (the OpenRouter bearer-token path) is stored in cfg.AuthToken and that
// cfg.APIKey is empty. A transposed field assignment in loadConfig would
// silently route all Claude API calls through the wrong header — "x-api-key"
// instead of "Authorization: Bearer" — causing every call to fail with a 401.
// The existing direct tests only exercise the ANTHROPIC_API_KEY path via
// setLoadConfigEnv; this closes the gap for the alternate auth path.
func TestLoadConfig_AuthTokenPathPreservesToken(t *testing.T) {
	t.Setenv("WEBHOOK_SECRET", "test-secret")
	t.Setenv("CHECKMK_API_USER", "test-user")
	t.Setenv("CHECKMK_API_SECRET", "test-api-secret")
	// Set auth token only; ensure API key is absent so loadConfig sees exactly
	// one auth var. Pattern: t.Setenv first (registers cleanup), then
	// os.Unsetenv so LookupEnv returns (_, false) rather than ("", true).
	t.Setenv("ANTHROPIC_API_KEY", "")
	os.Unsetenv("ANTHROPIC_API_KEY")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "test-auth-token")

	cfg := loadConfig()
	if cfg.AuthToken != "test-auth-token" {
		t.Errorf("AuthToken = %q, want %q", cfg.AuthToken, "test-auth-token")
	}
	if cfg.APIKey != "" {
		t.Errorf("APIKey = %q, want empty when using AuthToken path", cfg.APIKey)
	}
	// Both Anthropic vars must be cleared from the process env regardless of
	// which auth path was used — loadConfig is the single source of truth.
	if _, ok := os.LookupEnv("ANTHROPIC_AUTH_TOKEN"); ok {
		t.Error("ANTHROPIC_AUTH_TOKEN still in env after loadConfig")
	}
	if _, ok := os.LookupEnv("ANTHROPIC_API_KEY"); ok {
		t.Error("ANTHROPIC_API_KEY still in env after loadConfig")
	}
}

// TestLoadConfig_SSHEnabledDefaultsTrue verifies that SSH_ENABLED defaults to
// true when unset. SSH is the primary agentic diagnostic channel in the
// checkmk analyzer; operators who do not set SSH_ENABLED must get SSH-enabled
// behaviour rather than silently losing diagnostic capability.
func TestLoadConfig_SSHEnabledDefaultsTrue(t *testing.T) {
	setLoadConfigEnv(t)
	t.Setenv("SSH_ENABLED", "")
	os.Unsetenv("SSH_ENABLED")

	cfg := loadConfig()
	if !cfg.SSHEnabled {
		t.Errorf("SSHEnabled = false, want true (default must be true when SSH_ENABLED is unset)")
	}
}

// TestLoadConfig_SSHEnabledCanBeDisabled verifies that SSH_ENABLED=false is
// honoured and causes loadConfig to return SSHEnabled=false. Operators in
// environments without SSH access must be able to opt out of SSH diagnostics
// without disabling the entire analyzer.
func TestLoadConfig_SSHEnabledCanBeDisabled(t *testing.T) {
	setLoadConfigEnv(t)
	t.Setenv("SSH_ENABLED", "false")

	cfg := loadConfig()
	if cfg.SSHEnabled {
		t.Errorf("SSHEnabled = true, want false when SSH_ENABLED=false")
	}
}

// TestLoadConfig_CheckmkAPITimeoutIsPreserved verifies that a valid positive
// CHECKMK_API_TIMEOUT value is stored in Config.CheckMKAPITimeout. The existing
// test suite only covers invalid and negative values via subprocess tests; no
// direct-call test verified that a valid duration propagates to the correct
// struct field. A field-dropped or misassigned timeout would silently cause
// all CheckMK REST API calls to use the default (10 s) regardless of the
// operator's configuration, masking the misconfiguration until a slow server
// exposes it at runtime.
func TestLoadConfig_CheckmkAPITimeoutIsPreserved(t *testing.T) {
	setLoadConfigEnv(t)
	t.Setenv("CHECKMK_API_TIMEOUT", "45s")

	cfg := loadConfig()
	if cfg.CheckMKAPITimeout != 45*time.Second {
		t.Errorf("CheckMKAPITimeout = %v, want %v", cfg.CheckMKAPITimeout, 45*time.Second)
	}
}

// TestLoadConfig_CheckMKCredentialsArePreserved verifies that CHECKMK_API_USER
// and CHECKMK_API_SECRET are stored in the correct Config fields. The two
// values are fetched by adjacent RequireEnv calls and then assigned to adjacent
// struct fields — a single-character typo or copy-paste swap would silently
// send the secret as the username and the username as the secret, causing every
// CheckMK REST API call to return 401 without any obvious config-time error.
func TestLoadConfig_CheckMKCredentialsArePreserved(t *testing.T) {
	t.Setenv("WEBHOOK_SECRET", "test-secret")
	t.Setenv("CHECKMK_API_USER", "the-cmk-user")
	t.Setenv("CHECKMK_API_SECRET", "the-cmk-secret")
	t.Setenv("ANTHROPIC_API_KEY", "test-api-key")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "")
	os.Unsetenv("ANTHROPIC_AUTH_TOKEN")

	cfg := loadConfig()
	if cfg.CheckMKAPIUser != "the-cmk-user" {
		t.Errorf("CheckMKAPIUser = %q, want %q", cfg.CheckMKAPIUser, "the-cmk-user")
	}
	if cfg.CheckMKAPISecret != "the-cmk-secret" {
		t.Errorf("CheckMKAPISecret = %q, want %q", cfg.CheckMKAPISecret, "the-cmk-secret")
	}
}

// TestLoadConfig_SSHConfigDefaultsArePreserved verifies that the SSH config
// fields (SSHUser, SSHKeyPath, SSHKnownHostsPath) carry their documented
// default values when the corresponding env vars are not set. These defaults
// are the paths used by the in-cluster Deployment manifest; an operator who
// does not override them expects the analyzer to find the key at /ssh/id_ed25519
// and the known_hosts at /ssh/known_hosts, and to connect as the "nagios" user.
// A dropped or transposed EnvOrDefault call would silently look in the wrong
// place, causing every SSH connection to fail with a cryptic "no such file"
// error rather than a clear config message.
func TestLoadConfig_SSHConfigDefaultsArePreserved(t *testing.T) {
	setLoadConfigEnv(t)
	// Unset SSH config overrides so loadConfig uses EnvOrDefault fallbacks.
	for _, key := range []string{"SSH_USER", "SSH_KEY_PATH", "SSH_KNOWN_HOSTS_PATH"} {
		t.Setenv(key, "")
		os.Unsetenv(key)
	}

	cfg := loadConfig()
	if cfg.SSHUser != "nagios" {
		t.Errorf("SSHUser = %q, want %q", cfg.SSHUser, "nagios")
	}
	if cfg.SSHKeyPath != "/ssh/id_ed25519" {
		t.Errorf("SSHKeyPath = %q, want %q", cfg.SSHKeyPath, "/ssh/id_ed25519")
	}
	if cfg.SSHKnownHostsPath != "/ssh/known_hosts" {
		t.Errorf("SSHKnownHostsPath = %q, want %q", cfg.SSHKnownHostsPath, "/ssh/known_hosts")
	}
}

// TestLoadConfig_SSHDeniedCommandsParsing verifies that loadConfig correctly
// parses the SSH_DENIED_COMMANDS env var into Config.SSHDeniedCommands. The
// three distinct cases—unset (nil → default denylist), empty (no denylist),
// and a comma-separated list—each produce different runtime behaviour in
// RunAgenticDiagnostics. Trim and lowercase normalisation is also checked
// because the map stores lowercase keys and isDenied lowercases argv[0]
// before lookup; a mismatch would silently allow commands that should be
// blocked.
func TestLoadConfig_SSHDeniedCommandsParsing(t *testing.T) {
	t.Run("unset means nil (uses DefaultDeniedCommands)", func(t *testing.T) {
		setLoadConfigEnv(t)
		// Use the stormProtectionUnsetAll pattern: t.Setenv registers cleanup
		// to restore the original, then os.Unsetenv makes LookupEnv return
		// (_, false) so the if-block in loadConfig is not entered.
		t.Setenv("SSH_DENIED_COMMANDS", "")
		os.Unsetenv("SSH_DENIED_COMMANDS")

		cfg := loadConfig()
		if cfg.SSHDeniedCommands != nil {
			t.Errorf("SSHDeniedCommands: got %v, want nil (default denylist)", cfg.SSHDeniedCommands)
		}
	})

	t.Run("empty string means empty map (all commands allowed)", func(t *testing.T) {
		setLoadConfigEnv(t)
		t.Setenv("SSH_DENIED_COMMANDS", "")
		// SSH_DENIED_COMMANDS is set to "" — LookupEnv returns ("", true) so
		// the parsing block is entered but produces an empty map.

		cfg := loadConfig()
		if cfg.SSHDeniedCommands == nil {
			t.Fatal("SSHDeniedCommands: got nil, want non-nil empty map (empty value disables denylist)")
		}
		if len(cfg.SSHDeniedCommands) != 0 {
			t.Errorf("SSHDeniedCommands len: got %d, want 0", len(cfg.SSHDeniedCommands))
		}
	})

	t.Run("comma-separated list is stored as a map", func(t *testing.T) {
		setLoadConfigEnv(t)
		t.Setenv("SSH_DENIED_COMMANDS", "rm,mv,cp")

		cfg := loadConfig()
		if cfg.SSHDeniedCommands == nil {
			t.Fatal("SSHDeniedCommands: got nil, want non-nil map")
		}
		for _, cmd := range []string{"rm", "mv", "cp"} {
			if !cfg.SSHDeniedCommands[cmd] {
				t.Errorf("SSHDeniedCommands[%q] = false, want true", cmd)
			}
		}
		if len(cfg.SSHDeniedCommands) != 3 {
			t.Errorf("SSHDeniedCommands len: got %d, want 3", len(cfg.SSHDeniedCommands))
		}
	})

	t.Run("entries are trimmed and lowercased", func(t *testing.T) {
		setLoadConfigEnv(t)
		t.Setenv("SSH_DENIED_COMMANDS", "  RM  ,  MV  ")

		cfg := loadConfig()
		if cfg.SSHDeniedCommands == nil {
			t.Fatal("SSHDeniedCommands: got nil, want non-nil map")
		}
		if !cfg.SSHDeniedCommands["rm"] {
			t.Errorf(`SSHDeniedCommands["rm"] = false, want true (input was "  RM  ")`)
		}
		if !cfg.SSHDeniedCommands["mv"] {
			t.Errorf(`SSHDeniedCommands["mv"] = false, want true (input was "  MV  ")`)
		}
		if len(cfg.SSHDeniedCommands) != 2 {
			t.Errorf("SSHDeniedCommands len: got %d, want 2", len(cfg.SSHDeniedCommands))
		}
	})
}
