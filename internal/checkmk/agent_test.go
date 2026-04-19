package checkmk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
	"golang.org/x/crypto/ssh"
)

// capturingToolRunner invokes handleTool for each pre-configured call,
// records the results, then returns a fixed final response. This exercises
// the handleTool closure inside RunAgenticDiagnostics without a Claude API.
type capturingToolRunner struct {
	calls                []agentToolCall
	toolOutputs          []string
	toolErrors           []error
	result               string
	err                  error
	capturedSystemPrompt string
	capturedMaxRounds    int
}

type agentToolCall struct {
	name  string
	input string
}

func (r *capturingToolRunner) RunToolLoop(
	_ context.Context, systemPrompt, _ string,
	_ []shared.Tool, maxRounds int,
	handleTool func(string, json.RawMessage) (string, error),
) (string, error) {
	r.capturedSystemPrompt = systemPrompt
	r.capturedMaxRounds = maxRounds
	for _, call := range r.calls {
		out, err := handleTool(call.name, json.RawMessage(call.input))
		r.toolOutputs = append(r.toolOutputs, out)
		r.toolErrors = append(r.toolErrors, err)
	}
	return r.result, r.err
}

// fixedDialer always returns the same pre-connected SSH client (or error).
type fixedDialer struct {
	client *ssh.Client
	err    error
}

func (d *fixedDialer) Dial(_, _ string) (*ssh.Client, error) {
	return d.client, d.err
}

func TestRunAgenticDiagnostics_DialFailure(t *testing.T) {
	dialer := &fixedDialer{err: fmt.Errorf("connection refused")}
	runner := &capturingToolRunner{result: "should not reach"}

	_, err := RunAgenticDiagnostics(context.Background(), Config{}, runner, dialer, "host1", "10.0.0.1", "ctx", 3)
	if err == nil {
		t.Fatal("expected error when dial fails")
	}
	if !strings.Contains(err.Error(), "SSH connection failed") {
		t.Errorf("error should mention SSH connection failure, got: %v", err)
	}
}

func TestRunAgenticDiagnostics_DeniedCommandBlocked(t *testing.T) {
	sshCalled := false
	client := startTestSSHServer(t, func(_ string, ch ssh.Channel) {
		sshCalled = true
		sendExitStatus(ch, 0)
	})

	runner := &capturingToolRunner{
		calls:  []agentToolCall{{name: "execute_command", input: `{"command": ["rm", "-rf", "/"]}`}},
		result: "final analysis",
	}
	dialer := &fixedDialer{client: client}

	analysis, err := RunAgenticDiagnostics(
		context.Background(), Config{SSHDeniedCommands: DefaultDeniedCommands},
		runner, dialer, "host1", "10.0.0.1", "ctx", 3,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if analysis != "final analysis" {
		t.Errorf("got analysis %q", analysis)
	}
	if sshCalled {
		t.Error("SSH server should not be called for denied command")
	}
	if len(runner.toolOutputs) != 1 {
		t.Fatalf("expected 1 tool output, got %d", len(runner.toolOutputs))
	}
	if !strings.Contains(runner.toolOutputs[0], "denied") {
		t.Errorf("expected denial message in output, got: %q", runner.toolOutputs[0])
	}
	if runner.toolErrors[0] != nil {
		t.Errorf("expected nil error for denied command, got: %v", runner.toolErrors[0])
	}
}

func TestRunAgenticDiagnostics_AllowedCommandExecuted(t *testing.T) {
	client := startTestSSHServer(t, func(_ string, ch ssh.Channel) {
		_, _ = io.WriteString(ch, "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        50G   20G   30G  40% /\n")
		sendExitStatus(ch, 0)
	})

	runner := &capturingToolRunner{
		calls:  []agentToolCall{{name: "execute_command", input: `{"command": ["df", "-h"]}`}},
		result: "disk analysis",
	}
	dialer := &fixedDialer{client: client}

	analysis, err := RunAgenticDiagnostics(
		context.Background(), Config{SSHDeniedCommands: DefaultDeniedCommands},
		runner, dialer, "host1", "10.0.0.1", "ctx", 3,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if analysis != "disk analysis" {
		t.Errorf("got analysis %q", analysis)
	}
	if len(runner.toolOutputs) != 1 {
		t.Fatalf("expected 1 tool output, got %d", len(runner.toolOutputs))
	}
	if !strings.Contains(runner.toolOutputs[0], "Filesystem") {
		t.Errorf("expected SSH output in tool result, got: %q", runner.toolOutputs[0])
	}
	if !strings.Contains(runner.toolOutputs[0], "$ df -h") {
		t.Errorf("expected command echo in tool result, got: %q", runner.toolOutputs[0])
	}
}

func TestRunAgenticDiagnostics_UnknownToolReturnsError(t *testing.T) {
	client := startTestSSHServer(t, func(_ string, ch ssh.Channel) {
		sendExitStatus(ch, 0)
	})

	runner := &capturingToolRunner{
		calls:  []agentToolCall{{name: "unknown_tool", input: `{}`}},
		result: "analysis",
	}
	dialer := &fixedDialer{client: client}

	_, err := RunAgenticDiagnostics(
		context.Background(), Config{SSHDeniedCommands: DefaultDeniedCommands},
		runner, dialer, "host1", "10.0.0.1", "ctx", 3,
	)
	if err != nil {
		t.Fatalf("unexpected top-level error: %v", err)
	}
	if len(runner.toolErrors) != 1 {
		t.Fatalf("expected 1 tool error captured, got %d", len(runner.toolErrors))
	}
	if runner.toolErrors[0] == nil {
		t.Error("expected error for unknown tool, got nil")
	}
	if !strings.Contains(runner.toolErrors[0].Error(), "unknown tool") {
		t.Errorf("unexpected error: %v", runner.toolErrors[0])
	}
}

func TestRunAgenticDiagnostics_OutputRedacted(t *testing.T) {
	client := startTestSSHServer(t, func(_ string, ch ssh.Channel) {
		_, _ = io.WriteString(ch, "config: password=supersecret123\n")
		sendExitStatus(ch, 0)
	})

	runner := &capturingToolRunner{
		calls:  []agentToolCall{{name: "execute_command", input: `{"command": ["cat", "/etc/app.conf"]}`}},
		result: "config analysis",
	}
	dialer := &fixedDialer{client: client}

	_, err := RunAgenticDiagnostics(
		context.Background(), Config{SSHDeniedCommands: DefaultDeniedCommands},
		runner, dialer, "host1", "10.0.0.1", "ctx", 3,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(runner.toolOutputs) != 1 {
		t.Fatalf("expected 1 tool output, got %d", len(runner.toolOutputs))
	}
	if strings.Contains(runner.toolOutputs[0], "supersecret123") {
		t.Errorf("secret leaked in tool output: %q", runner.toolOutputs[0])
	}
	if !strings.Contains(runner.toolOutputs[0], "[REDACTED]") {
		t.Errorf("expected [REDACTED] in output, got: %q", runner.toolOutputs[0])
	}
}

// TestRunAgenticDiagnostics_NonZeroExitIncludesOutput verifies that when a diagnostic
// command exits with a non-zero status but produced output (e.g. "systemctl status"
// on a stopped service exits 3 with useful status text), the output is preserved in
// the tool result rather than being silently discarded. Without this, Claude only sees
// "Command failed: exit status 3" instead of the actual service status output.
func TestRunAgenticDiagnostics_NonZeroExitIncludesOutput(t *testing.T) {
	const systemctlOutput = "● nginx.service - A high performance web server\n   Loaded: loaded\n   Active: failed (Result: exit-code)\n"
	client := startTestSSHServer(t, func(_ string, ch ssh.Channel) {
		_, _ = io.WriteString(ch, systemctlOutput)
		sendExitStatus(ch, 3) // systemctl status exits 3 when unit is stopped/failed
	})

	runner := &capturingToolRunner{
		calls:  []agentToolCall{{name: "execute_command", input: `{"command": ["systemctl", "status", "nginx"]}`}},
		result: "nginx analysis",
	}
	dialer := &fixedDialer{client: client}

	_, err := RunAgenticDiagnostics(
		context.Background(), Config{SSHDeniedCommands: DefaultDeniedCommands},
		runner, dialer, "host1", "10.0.0.1", "ctx", 3,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(runner.toolOutputs) != 1 {
		t.Fatalf("expected 1 tool output, got %d", len(runner.toolOutputs))
	}
	// The output must contain the systemctl status text, not just an error message.
	if !strings.Contains(runner.toolOutputs[0], "nginx.service") {
		t.Errorf("expected systemctl output in tool result for non-zero exit, got: %q", runner.toolOutputs[0])
	}
	// The exit status should also be noted so Claude knows the command failed.
	if !strings.Contains(runner.toolOutputs[0], "exited") {
		t.Errorf("expected exit status annotation in tool result, got: %q", runner.toolOutputs[0])
	}
	// Must not be a bare "Command failed" message — the output must be included.
	if strings.HasPrefix(runner.toolOutputs[0], "Command failed:") && !strings.Contains(runner.toolOutputs[0], "nginx") {
		t.Errorf("tool output discards command output for non-zero exit, got: %q", runner.toolOutputs[0])
	}
}

func TestIsDenied_BlocksDestructiveCommands(t *testing.T) {
	denied := [][]string{
		{"rm", "-rf", "/"},
		{"sudo", "cat", "/etc/shadow"},
		{"su", "-", "root"},
		{"shutdown", "-h", "now"},
		{"reboot"},
		{"dd", "if=/dev/zero", "of=/dev/sda"},
		{"chmod", "777", "/etc/passwd"},
		{"kill", "-9", "1"},
		{"mv", "/etc/hosts", "/tmp/"},
		{"tee", "/etc/cron.d/backdoor"},
		{"iptables", "-F"},
		{"mount", "/dev/sdb1", "/mnt"},
		{"pkexec", "bash"},
		{"doas", "sh"},
		{"passwd", "root"},
		{"crontab", "-e"},
		{"nft", "flush", "ruleset"},
		{"useradd", "hacker"},
		{"chown", "root:root", "/tmp/foo"},
	}
	for _, argv := range denied {
		if !isDenied(DefaultDeniedCommands, argv) {
			t.Errorf("expected denied: %v", argv)
		}
	}
}

// TestIsDenied_BlocksTee verifies that tee is blocked. tee opens its output
// file(s) with O_TRUNC before reading stdin, so "tee /path/to/file" truncates
// the file to zero bytes even when SSH stdin is empty. This makes it as
// dangerous as cp/mv for file destruction and must be denied alongside them.
func TestIsDenied_BlocksTee(t *testing.T) {
	denied := [][]string{
		{"tee", "/etc/passwd"},
		{"tee", "-a", "/etc/cron.d/job"},
		{"/usr/bin/tee", "/tmp/writeable"},
	}
	for _, argv := range denied {
		if !isDenied(DefaultDeniedCommands, argv) {
			t.Errorf("expected tee variant denied: %v", argv)
		}
	}
}

// TestIsDenied_BlocksShellInterpreterBypass verifies that shells and interpreters
// are denied so that Claude cannot bypass the denylist by wrapping a destructive
// command in "bash -c 'rm -rf /'" or "python3 -c 'import os; os.system(...)'"
// or routing it through "env rm -rf /" / "xargs rm".
func TestIsDenied_BlocksShellInterpreterBypass(t *testing.T) {
	denied := [][]string{
		{"bash", "-c", "rm -rf /"},
		{"sh", "-c", "shutdown now"},
		{"dash", "-c", "reboot"},
		{"zsh", "-c", "kill -9 1"},
		{"fish", "-c", "dd if=/dev/zero of=/dev/sda"},
		{"python", "-c", "import os; os.system('rm -rf /')"},
		{"python2", "-c", "import os; os.system('rm -rf /')"},
		{"python3", "-c", "import os; os.system('rm -rf /')"},
		{"perl", "-e", "system('reboot')"},
		{"ruby", "-e", "system('shutdown now')"},
		{"node", "-e", "require('child_process').exec('rm -rf /')"},
		{"nodejs", "-e", "require('child_process').exec('rm -rf /')"},
		{"env", "rm", "-rf", "/"},
		{"xargs", "rm", "-rf"},
	}
	for _, argv := range denied {
		if !isDenied(DefaultDeniedCommands, argv) {
			t.Errorf("shell/interpreter bypass not blocked: %v", argv)
		}
	}
}

func TestIsDenied_AllowsReadOnlyCommands(t *testing.T) {
	allowed := [][]string{
		{"df", "-h"},
		{"free", "-h"},
		{"uptime"},
		{"top", "-bn1"},
		{"ps", "aux", "--sort=-%mem"},
		{"journalctl", "--no-pager", "-p", "err", "-n", "50"},
		{"cat", "/var/log/syslog"},
		{"ls", "-la", "/tmp"},
		{"netstat", "-tlnp"},
		{"ss", "-tlnp"},
		{"ip", "addr"},
		{"du", "-sh", "/var"},
		{"head", "-n", "100", "/var/log/messages"},
		{"tail", "-n", "50", "/var/log/syslog"},
		{"grep", "error", "/var/log/syslog"},
		{"find", "/var/log", "-name", "*.log"},
		{"lsblk"},
		{"lsof", "-i", ":80"},
	}
	for _, argv := range allowed {
		if isDenied(DefaultDeniedCommands, argv) {
			t.Errorf("expected allowed: %v", argv)
		}
	}
}

func TestIsDenied_SystemctlSpecialCases(t *testing.T) {
	allowed := [][]string{
		{"systemctl", "status", "nginx"},
		{"systemctl", "show", "sshd"},
		{"systemctl", "list-units", "--failed"},
		{"systemctl", "is-active", "docker"},
		{"systemctl", "is-failed", "nginx"},
		{"systemctl", "list-timers"},
	}
	for _, argv := range allowed {
		if isDenied(DefaultDeniedCommands, argv) {
			t.Errorf("expected allowed: %v", argv)
		}
	}

	denied := [][]string{
		{"systemctl", "restart", "nginx"},
		{"systemctl", "stop", "sshd"},
		{"systemctl", "start", "docker"},
		{"systemctl", "enable", "foo"},
		{"systemctl", "disable", "bar"},
		{"systemctl", "mask", "firewalld"},
		{"systemctl", "daemon-reload"},
	}
	for _, argv := range denied {
		if !isDenied(DefaultDeniedCommands, argv) {
			t.Errorf("expected denied: %v", argv)
		}
	}
}

func TestIsDenied_EmptyCommand(t *testing.T) {
	if !isDenied(DefaultDeniedCommands, nil) {
		t.Error("expected denied for nil")
	}
	if !isDenied(DefaultDeniedCommands, []string{}) {
		t.Error("expected denied for empty")
	}
}

func TestIsDenied_EmptyDenylist(t *testing.T) {
	empty := map[string]bool{}
	// With empty denylist, everything is allowed (except empty commands)
	if !isDenied(empty, nil) {
		t.Error("expected denied for nil even with empty denylist")
	}
	if isDenied(empty, []string{"rm", "-rf", "/"}) {
		t.Error("expected allowed with empty denylist")
	}
	if isDenied(empty, []string{"sudo", "cat", "/etc/shadow"}) {
		t.Error("expected allowed with empty denylist")
	}
	if isDenied(empty, []string{"systemctl", "restart", "nginx"}) {
		t.Error("expected systemctl restart allowed with empty denylist")
	}
}

func TestIsDenied_CustomDenylist(t *testing.T) {
	custom := map[string]bool{"rm": true, "dd": true}
	if !isDenied(custom, []string{"rm", "-rf", "/"}) {
		t.Error("expected rm denied with custom list")
	}
	if isDenied(custom, []string{"sudo", "cat", "/etc/shadow"}) {
		t.Error("expected sudo allowed with custom list (not in denylist)")
	}
	if isDenied(custom, []string{"reboot"}) {
		t.Error("expected reboot allowed with custom list")
	}
}

func TestIsDenied_SystemctlAlwaysChecked(t *testing.T) {
	// Custom denylist that does NOT include "systemctl"
	custom := map[string]bool{"rm": true, "dd": true}

	// Destructive systemctl subcommands must be denied even without
	// "systemctl" in the denylist.
	denied := [][]string{
		{"systemctl", "restart", "nginx"},
		{"systemctl", "stop", "sshd"},
		{"systemctl", "start", "docker"},
		{"systemctl", "enable", "foo"},
		{"systemctl", "disable", "bar"},
		{"systemctl", "mask", "firewalld"},
		{"systemctl", "daemon-reload"},
	}
	for _, argv := range denied {
		if !isDenied(custom, argv) {
			t.Errorf("expected denied with custom denylist: %v", argv)
		}
	}

	// Bare systemctl (no subcommand) must also be denied.
	if !isDenied(custom, []string{"systemctl"}) {
		t.Error("expected bare systemctl denied with custom denylist")
	}

	// Read-only subcommands must still be allowed.
	allowed := [][]string{
		{"systemctl", "status", "nginx"},
		{"systemctl", "show", "sshd"},
		{"systemctl", "is-active", "docker"},
		{"systemctl", "is-failed", "nginx"},
		{"systemctl", "list-units", "--failed"},
		{"systemctl", "list-timers"},
	}
	for _, argv := range allowed {
		if isDenied(custom, argv) {
			t.Errorf("expected allowed with custom denylist: %v", argv)
		}
	}
}

func TestParseCommandInput(t *testing.T) {
	input := json.RawMessage(`{"command": ["df", "-h"]}`)
	argv, err := parseCommandInput(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(argv) != 2 || argv[0] != "df" || argv[1] != "-h" {
		t.Errorf("unexpected argv: %v", argv)
	}
}

func TestParseCommandInput_Invalid(t *testing.T) {
	cases := []string{
		`{}`,
		`{"command": "not-array"}`,
		`{"command": []}`,
	}
	for _, c := range cases {
		_, err := parseCommandInput(json.RawMessage(c))
		if err == nil {
			t.Errorf("expected error for input: %s", c)
		}
	}
}

func TestIsDenied_SystemctlFlagsBeforeSubcommand(t *testing.T) {
	// Flags like --no-pager or --user before the subcommand are common in
	// practice (Claude naturally adds --no-pager to suppress paging).
	// They must not cause a valid read-only subcommand to be denied.
	allowed := [][]string{
		{"systemctl", "--no-pager", "status", "nginx"},
		{"systemctl", "--no-pager", "show", "sshd"},
		{"systemctl", "--user", "status"},
		{"systemctl", "--no-pager", "list-units", "--failed"},
		{"/usr/bin/systemctl", "--no-pager", "is-active", "docker"},
	}
	for _, argv := range allowed {
		if isDenied(DefaultDeniedCommands, argv) {
			t.Errorf("expected allowed (flags before subcommand): %v", argv)
		}
	}

	// Flags before a destructive subcommand must still be denied.
	denied := [][]string{
		{"systemctl", "--no-pager", "restart", "nginx"},
		{"systemctl", "--user", "stop", "sshd"},
		{"systemctl", "--no-pager", "daemon-reload"},
	}
	for _, argv := range denied {
		if !isDenied(DefaultDeniedCommands, argv) {
			t.Errorf("expected denied (flags before destructive subcommand): %v", argv)
		}
	}

	// Only flags with no subcommand must be denied.
	if !isDenied(DefaultDeniedCommands, []string{"systemctl", "--no-pager"}) {
		t.Error("expected denied: systemctl with only flags and no subcommand")
	}
}

func TestIsDenied_AbsolutePathBypassBlocked(t *testing.T) {
	// Absolute paths like /bin/rm must be treated the same as bare "rm".
	denied := [][]string{
		{"/bin/rm", "-rf", "/"},
		{"/usr/bin/sudo", "cat", "/etc/shadow"},
		{"/sbin/shutdown", "-h", "now"},
		{"/usr/sbin/reboot"},
		{"/bin/dd", "if=/dev/zero", "of=/dev/sda"},
	}
	for _, argv := range denied {
		if !isDenied(DefaultDeniedCommands, argv) {
			t.Errorf("expected denied (absolute path): %v", argv)
		}
	}
}

func TestIsDenied_RelativePathBypassBlocked(t *testing.T) {
	// Relative paths like ./rm must also be caught.
	denied := [][]string{
		{"./rm", "-rf", "/"},
		{"../bin/sudo", "bash"},
		{"./shutdown", "now"},
	}
	for _, argv := range denied {
		if !isDenied(DefaultDeniedCommands, argv) {
			t.Errorf("expected denied (relative path): %v", argv)
		}
	}
}

func TestIsDenied_AbsolutePathSystemctl(t *testing.T) {
	// /usr/bin/systemctl with destructive subcommands must be denied.
	denied := [][]string{
		{"/usr/bin/systemctl", "restart", "nginx"},
		{"/bin/systemctl", "stop", "sshd"},
	}
	for _, argv := range denied {
		if !isDenied(DefaultDeniedCommands, argv) {
			t.Errorf("expected denied (absolute path systemctl): %v", argv)
		}
	}

	// /usr/bin/systemctl with read-only subcommands must be allowed.
	allowed := [][]string{
		{"/usr/bin/systemctl", "status", "nginx"},
		{"/bin/systemctl", "is-active", "docker"},
	}
	for _, argv := range allowed {
		if isDenied(DefaultDeniedCommands, argv) {
			t.Errorf("expected allowed (absolute path systemctl read-only): %v", argv)
		}
	}
}

// TestAgentSystemPromptForRounds verifies that agentSystemPromptForRounds injects
// the actual maxRounds value into the prompt text. If MAX_AGENT_ROUNDS is changed
// from the default of 10, Claude must see the correct number so it can plan its
// diagnostic rounds accurately.
func TestAgentSystemPromptForRounds(t *testing.T) {
	cases := []struct {
		maxRounds int
	}{
		{1},
		{5},
		{10},
		{15},
		{50},
	}
	for _, tc := range cases {
		prompt := agentSystemPromptForRounds(tc.maxRounds)
		wantSubstring := fmt.Sprintf("maximum of %d command rounds", tc.maxRounds)
		if !strings.Contains(prompt, wantSubstring) {
			t.Errorf("agentSystemPromptForRounds(%d): expected %q in prompt, got:\n%s",
				tc.maxRounds, wantSubstring, prompt)
		}
	}
}

// TestRunAgenticDiagnostics_SystemPromptContainsMaxRounds verifies that
// RunAgenticDiagnostics passes a system prompt reflecting the actual maxRounds
// to the tool runner. When an operator sets MAX_AGENT_ROUNDS to a non-default
// value, the prompt must mention that value so Claude plans accordingly.
func TestRunAgenticDiagnostics_SystemPromptContainsMaxRounds(t *testing.T) {
	client := startTestSSHServer(t, func(_ string, ch ssh.Channel) {
		sendExitStatus(ch, 0)
	})
	dialer := &fixedDialer{client: client}

	const customRounds = 5
	runner := &capturingToolRunner{result: "analysis"}

	_, err := RunAgenticDiagnostics(
		context.Background(), Config{SSHDeniedCommands: DefaultDeniedCommands},
		runner, dialer, "host1", "10.0.0.1", "ctx", customRounds,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantSubstring := fmt.Sprintf("maximum of %d command rounds", customRounds)
	if !strings.Contains(runner.capturedSystemPrompt, wantSubstring) {
		t.Errorf("system prompt does not reflect maxRounds=%d;\nwant substring: %q\ngot prompt:\n%s",
			customRounds, wantSubstring, runner.capturedSystemPrompt)
	}
	if runner.capturedMaxRounds != customRounds {
		t.Errorf("RunToolLoop received maxRounds=%d, want %d",
			runner.capturedMaxRounds, customRounds)
	}
}

// TestIsDenied_FindExecBlocked verifies that find with -exec/-execdir/-ok/-okdir
// is denied even when "find" is not in the denylist. These flags let find spawn
// arbitrary sub-processes for each matched file, which would bypass the denylist
// check (e.g. "find / -exec rm {} ;" runs rm without any denylist check on rm).
func TestIsDenied_FindExecBlocked(t *testing.T) {
	// All exec-capable flags must be denied with the default denylist.
	denied := [][]string{
		{"find", "/", "-exec", "rm", "{}", ";"},
		{"find", "/var/log", "-execdir", "cat", "{}", ";"},
		{"find", "/", "-ok", "rm", "{}", ";"},
		{"find", "/", "-okdir", "chmod", "+x", "{}", ";"},
		// Absolute path to find must still trigger the exec check.
		{"/usr/bin/find", "/", "-exec", "sh", "-c", "rm -rf /", ";"},
		// -exec to run a read-only command is still denied (we can't inspect
		// the sub-command safely, so all -exec uses are blocked).
		{"find", "/var/log", "-name", "*.log", "-exec", "cat", "{}", ";"},
	}
	for _, argv := range denied {
		if !isDenied(DefaultDeniedCommands, argv) {
			t.Errorf("expected find -exec variant denied: %v", argv)
		}
	}
}

// TestIsDenied_FindReadOnlyAllowed verifies that find without exec flags is
// still allowed for diagnostic use (listing files, filtering by name/time, etc.).
func TestIsDenied_FindReadOnlyAllowed(t *testing.T) {
	allowed := [][]string{
		{"find", "/var/log", "-name", "*.log"},
		{"find", "/etc", "-type", "f"},
		{"find", "/var/log", "-mtime", "-1"},
		{"find", "/", "-name", "core", "-type", "f"},
		{"/usr/bin/find", "/tmp", "-newer", "/etc/hosts"},
	}
	for _, argv := range allowed {
		if isDenied(DefaultDeniedCommands, argv) {
			t.Errorf("expected read-only find allowed: %v", argv)
		}
	}
}

// TestIsDenied_FindExecAlwaysChecked verifies that find -exec is denied even
// when a custom denylist does not include "find". This is the same defence-in-
// depth guarantee that applies to systemctl (always checked for destructive
// subcommands regardless of the denylist contents).
func TestIsDenied_FindExecAlwaysChecked(t *testing.T) {
	// Custom denylist that does NOT include "find".
	custom := map[string]bool{"rm": true, "dd": true}

	denied := [][]string{
		{"find", "/", "-exec", "rm", "{}", ";"},
		{"find", "/var/log", "-execdir", "cat", "{}", ";"},
		{"find", "/", "-ok", "rm", "{}", ";"},
		{"find", "/", "-okdir", "chmod", "+x", "{}", ";"},
	}
	for _, argv := range denied {
		if !isDenied(custom, argv) {
			t.Errorf("find exec variant not blocked with custom denylist: %v", argv)
		}
	}

	// Read-only find must still be allowed with the custom denylist.
	allowed := [][]string{
		{"find", "/var/log", "-name", "*.log"},
		{"find", "/etc", "-type", "f"},
	}
	for _, argv := range allowed {
		if isDenied(custom, argv) {
			t.Errorf("read-only find should be allowed with custom denylist: %v", argv)
		}
	}
}
