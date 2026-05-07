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
