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
