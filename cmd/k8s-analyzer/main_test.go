package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
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

// TestMain_FailsWhenStormModeNotifyIntervalNegative verifies that a negative
// STORM_MODE_NOTIFY_INTERVAL is rejected at startup. A negative duration is a
// valid Go duration string but LoadStormProtectionConfig rejects values <= 0.
// Mirrors TestMain_FailsWhenKubeAPITimeoutNegative for the notify-interval path.
func TestMain_FailsWhenStormModeNotifyIntervalNegative(t *testing.T) {
	env := minEnv()
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
	env := minEnv()
	env["CIRCUIT_BREAKER_NOTIFY_INTERVAL"] = "-30s"
	exit, out := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for negative CIRCUIT_BREAKER_NOTIFY_INTERVAL; output=%s", out)
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

// TestMain_FailsWhenKubeAPITimeoutNegative verifies that a negative
// KUBE_API_TIMEOUT is rejected at startup. A negative duration is a valid Go
// duration string but creates an already-expired context, causing all Kubernetes
// API calls to fail immediately with context.DeadlineExceeded.
func TestMain_FailsWhenKubeAPITimeoutNegative(t *testing.T) {
	env := minEnv()
	env["KUBE_API_TIMEOUT"] = "-1s"
	exit, out := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for negative KUBE_API_TIMEOUT; output=%s", out)
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

// TestMain_FailsWhenPromTimeoutNegative verifies that a negative PROM_TIMEOUT
// is rejected at startup. A negative duration is a valid Go duration string but
// creates an already-expired context, causing all Prometheus API calls to fail
// immediately with context.DeadlineExceeded.
func TestMain_FailsWhenPromTimeoutNegative(t *testing.T) {
	env := minEnv()
	env["PROM_TIMEOUT"] = "-1s"
	exit, out := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for negative PROM_TIMEOUT; output=%s", out)
	}
	if !strings.Contains(out, "PROM_TIMEOUT") {
		t.Errorf("expected 'PROM_TIMEOUT' in output, got: %s", out)
	}
}

// TestMain_FailsWhenMaxAgentRoundsInvalid verifies that the binary exits and
// logs an error mentioning MAX_AGENT_ROUNDS when the value is outside the valid
// range [1, 50]. LoadPolicy is called in main() after loadConfig() but before
// rest.InClusterConfig(), so minEnv() is sufficient to reach this validation.
// MAX_AGENT_ROUNDS=0 is below the minimum (1 round = at least one tool loop);
// the binary must fail fast rather than silently defaulting to 0 which would
// cause all agentic analysis to be skipped without operator awareness.
func TestMain_FailsWhenMaxAgentRoundsInvalid(t *testing.T) {
	env := minEnv()
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
// LoadPolicy, which is called after loadConfig() but before rest.InClusterConfig(),
// so minEnv() is sufficient to reach this validation.
func TestMain_FailsWhenGroupCooldownSecondsInvalid(t *testing.T) {
	env := minEnv()
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
// LoadPolicy, which is called before rest.InClusterConfig(), so minEnv() is
// sufficient to reach this validation.
func TestMain_FailsWhenStormModeThresholdInvalid(t *testing.T) {
	env := minEnv()
	env["STORM_MODE_THRESHOLD"] = "100001" // exceeds max 100000
	exit, out := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for invalid STORM_MODE_THRESHOLD; output=%s", out)
	}
	if !strings.Contains(out, "STORM_MODE_THRESHOLD") {
		t.Errorf("expected 'STORM_MODE_THRESHOLD' in output, got: %s", out)
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

// TestMain_FailsWhenHistoryTTLInvalid verifies that the binary exits and logs
// an error mentioning HISTORY_TTL when the env var is not a valid Go duration
// string. LoadHistoryConfig is called in main() after loadConfig() and
// LoadStormProtectionConfig() but before rest.InClusterConfig(), so minEnv()
// is sufficient to reach this validation without a live cluster.
func TestMain_FailsWhenHistoryTTLInvalid(t *testing.T) {
	env := minEnv()
	env["HISTORY_TTL"] = "notaduration"
	exit, out := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for invalid HISTORY_TTL; output=%s", out)
	}
	if !strings.Contains(out, "HISTORY_TTL") {
		t.Errorf("expected 'HISTORY_TTL' in output, got: %s", out)
	}
}

// TestMain_FailsWhenHistoryTTLNegative verifies that a negative HISTORY_TTL is
// rejected at startup. A negative duration is a valid Go duration string but
// LoadHistoryConfig explicitly rejects ttl <= 0. Mirrors
// TestMain_FailsWhenKubeAPITimeoutNegative.
func TestMain_FailsWhenHistoryTTLNegative(t *testing.T) {
	env := minEnv()
	env["HISTORY_TTL"] = "-1h"
	exit, out := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for negative HISTORY_TTL; output=%s", out)
	}
	if !strings.Contains(out, "HISTORY_TTL") {
		t.Errorf("expected 'HISTORY_TTL' in output, got: %s", out)
	}
}

// TestMain_FailsWhenHistoryEnabledInvalid verifies that the binary exits and
// logs an error mentioning HISTORY_ENABLED when the env var is not a valid
// boolean. LoadHistoryConfig is called before rest.InClusterConfig() so
// minEnv() is sufficient to reach this path.
func TestMain_FailsWhenHistoryEnabledInvalid(t *testing.T) {
	env := minEnv()
	env["HISTORY_ENABLED"] = "notabool"
	exit, out := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for invalid HISTORY_ENABLED; output=%s", out)
	}
	if !strings.Contains(out, "HISTORY_ENABLED") {
		t.Errorf("expected 'HISTORY_ENABLED' in output, got: %s", out)
	}
}

// TestMain_FailsWhenHistoryMaxEntriesInvalid verifies that the binary exits
// and logs an error mentioning HISTORY_MAX_ENTRIES when the value is outside
// the valid range [1, 100]. Requires minEnv() to reach LoadHistoryConfig.
func TestMain_FailsWhenHistoryMaxEntriesInvalid(t *testing.T) {
	env := minEnv()
	env["HISTORY_MAX_ENTRIES"] = "0" // below min 1
	exit, out := runMainWithEnv(t, env)
	if exit == 0 {
		t.Fatalf("expected non-zero exit for invalid HISTORY_MAX_ENTRIES; output=%s", out)
	}
	if !strings.Contains(out, "HISTORY_MAX_ENTRIES") {
		t.Errorf("expected 'HISTORY_MAX_ENTRIES' in output, got: %s", out)
	}
}

// TestMain_FailsWhenHistoryInjectPriorInvalid verifies that the binary exits
// and logs an error mentioning HISTORY_INJECT_PRIOR when the env var is not a
// valid boolean. Requires minEnv() to reach LoadHistoryConfig.
func TestMain_FailsWhenHistoryInjectPriorInvalid(t *testing.T) {
	env := minEnv()
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

// TestLoadConfig_SkipResolvedDefaultsTrue verifies that SKIP_RESOLVED defaults
// to true when unset. Alertmanager sends resolved notifications for cleared
// alerts; skipping them by default prevents re-analysis of alerts that are
// no longer firing, which would waste API calls and confuse on-call responders.
func TestLoadConfig_SkipResolvedDefaultsTrue(t *testing.T) {
	setLoadConfigEnv(t)
	t.Setenv("SKIP_RESOLVED", "")
	os.Unsetenv("SKIP_RESOLVED")

	cfg := loadConfig()
	if !cfg.SkipResolved {
		t.Errorf("SkipResolved = false, want true (default must be true when SKIP_RESOLVED is unset)")
	}
}

// TestLoadConfig_SkipResolvedCanBeDisabled verifies that SKIP_RESOLVED=false
// is honoured and causes loadConfig to return SkipResolved=false. Operators
// who want resolved alerts to trigger a final analysis (e.g. to record the
// recovery in history) must be able to opt in.
func TestLoadConfig_SkipResolvedCanBeDisabled(t *testing.T) {
	setLoadConfigEnv(t)
	t.Setenv("SKIP_RESOLVED", "false")

	cfg := loadConfig()
	if cfg.SkipResolved {
		t.Errorf("SkipResolved = true, want false when SKIP_RESOLVED=false")
	}
}

// TestLoadConfig_TimeoutsArePreserved verifies that KUBE_API_TIMEOUT and
// PROM_TIMEOUT are stored in the correct Config fields when set to valid
// positive durations. A field-swapped or dropped assignment would silently
// cause context gatherers to use the wrong deadline, exposing the
// misconfiguration only at runtime against a slow API server or Prometheus.
func TestLoadConfig_TimeoutsArePreserved(t *testing.T) {
	setLoadConfigEnv(t)
	t.Setenv("KUBE_API_TIMEOUT", "45s")
	t.Setenv("PROM_TIMEOUT", "20s")

	cfg := loadConfig()
	if cfg.KubeAPITimeout != 45*time.Second {
		t.Errorf("KubeAPITimeout = %v, want %v", cfg.KubeAPITimeout, 45*time.Second)
	}
	if cfg.PromTimeout != 20*time.Second {
		t.Errorf("PromTimeout = %v, want %v", cfg.PromTimeout, 20*time.Second)
	}
}
