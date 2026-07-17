package checkmk

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
	"golang.org/x/crypto/ssh"
)

// runAdvisoryDiag runs RunAgenticDiagnostics with runSSHCommandFn stubbed to
// return r for every command, driving a single handleTool call for cmd and
// returning its tool-result string.
func runAdvisoryDiag(t *testing.T, r sshResult, cmd string) string {
	t.Helper()
	old := runSSHCommandFn
	runSSHCommandFn = func(_ context.Context, _ *ssh.Client, _ []string, _ time.Duration) sshResult {
		return r
	}
	t.Cleanup(func() { runSSHCommandFn = old })

	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetricsForTest(shared.ProductCheckMK)}
	var toolResult string
	runner := &driverToolLoopRunner{
		driver: func(handleTool func(string, json.RawMessage) (string, error)) (string, error) {
			out, err := handleTool("execute_command", json.RawMessage(cmd))
			if err != nil {
				t.Fatalf("handleTool unexpected error: %v", err)
			}
			toolResult = out
			return "analysis", nil
		},
	}
	_, err := RunAgenticDiagnostics(
		context.Background(), Config{SSHDeniedCommands: DefaultDeniedCommands},
		runner, nilDialer{}, metrics, shared.SeverityWarning, "host1", "10.0.0.1", "ctx", 10, "test-model",
	)
	if err != nil {
		t.Fatalf("RunAgenticDiagnostics returned unexpected error: %v", err)
	}
	return toolResult
}

// TestAgenticSSH_PermissionDeniedAdvisory verifies that a remote command
// failing with "Permission denied" on stderr gets a classification hint
// prepended, while the "[exit code: N]" trailer stays on the last line so
// wrappedHandleTool's outcome classification is unaffected (issue #35).
func TestAgenticSSH_PermissionDeniedAdvisory(t *testing.T) {
	out := runAdvisoryDiag(t,
		sshResult{output: "cat: /etc/shadow: Permission denied", exitCode: 1},
		`{"command":["cat","/etc/shadow"]}`)

	if !strings.HasPrefix(out, "[hint: ") {
		t.Fatalf("expected advisory hint prefix, got: %q", out)
	}
	firstLine := out[:strings.IndexByte(out, '\n')]
	if !strings.Contains(strings.ToLower(firstLine), "permission denied") {
		t.Errorf("expected permission-denied advisory in first line, got: %q", firstLine)
	}
	lastLine := out[strings.LastIndexByte(out, '\n')+1:]
	if lastLine != "[exit code: 1]" {
		t.Errorf("exit-code trailer must remain the last line, got: %q", lastLine)
	}
}

// TestAgenticSSH_TimeoutAdvisory verifies a transport-level timeout error is
// classified and hinted.
func TestAgenticSSH_TimeoutAdvisory(t *testing.T) {
	out := runAdvisoryDiag(t,
		sshResult{err: errTimeoutForTest("timeout after 10s")},
		`{"command":["journalctl","--no-pager"]}`)

	if !strings.HasPrefix(out, "[hint: ") {
		t.Fatalf("expected advisory hint prefix, got: %q", out)
	}
	if !strings.Contains(strings.ToLower(out[:strings.IndexByte(out, '\n')]), "timed out") {
		t.Errorf("expected timeout advisory in first line, got: %q", out)
	}
}

// TestAgenticSSH_NoAdvisoryFromLogContent verifies that error-like words
// inside remote command OUTPUT (here: log lines mentioning "connection
// refused") never produce an advisory on the exit-code path — only
// stderr-shaped classes (permission denied, command/file not found) apply
// there, so log content cannot mislead the model about transport health.
func TestAgenticSSH_NoAdvisoryFromLogContent(t *testing.T) {
	out := runAdvisoryDiag(t,
		sshResult{output: "May 30 dial tcp: connection refused\nMay 30 retrying", exitCode: 1},
		`{"command":["grep","refused","/var/log/app.log"]}`)

	if strings.Contains(out, "[hint: ") {
		t.Errorf("log content must not trigger an advisory on the exit-code path, got: %q", out)
	}
}

// TestAgenticSSH_CommandNotFoundAdvisory verifies the command-not-found class
// on the exit-code path.
func TestAgenticSSH_CommandNotFoundAdvisory(t *testing.T) {
	out := runAdvisoryDiag(t,
		sshResult{output: "bash: line 1: iotop: command not found", exitCode: 127},
		`{"command":["iotop","-b"]}`)

	if !strings.HasPrefix(out, "[hint: ") {
		t.Fatalf("expected advisory hint prefix, got: %q", out)
	}
	if !strings.Contains(strings.ToLower(out[:strings.IndexByte(out, '\n')]), "command not found") {
		t.Errorf("expected command-not-found advisory in first line, got: %q", out)
	}
}

// TestAgenticSSH_NoAdvisoryOnSuccess verifies successful commands are never
// prefixed with a hint even when their output contains error-like words.
func TestAgenticSSH_NoAdvisoryOnSuccess(t *testing.T) {
	out := runAdvisoryDiag(t,
		sshResult{output: "app.log:1: connection refused — permission denied for user bob"},
		`{"command":["tail","/var/log/app.log"]}`)

	if strings.Contains(out, "[hint: ") {
		t.Errorf("successful command must not carry an advisory, got: %q", out)
	}
}

// errTimeoutForTest is a trivial error type carrying a fixed message.
type errTimeoutForTest string

func (e errTimeoutForTest) Error() string { return string(e) }
