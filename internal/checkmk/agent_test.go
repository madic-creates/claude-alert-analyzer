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
	// Tool result must use the shell-quoted form so the prefix accurately
	// represents the command that was executed on the remote host.
	if !strings.Contains(runner.toolOutputs[0], "$ 'df' '-h'") {
		t.Errorf("expected shell-quoted command echo in tool result, got: %q", runner.toolOutputs[0])
	}
}

// TestRunAgenticDiagnostics_SpaceArgShellQuoted verifies that when a command
// argument contains a space (e.g. a grep pattern), the tool result prefix uses
// the shell-quoted form so Claude can distinguish multi-word arguments from
// separate tokens. Without quoting, "grep -r some pattern /var/log" looks like
// four arguments but "$ 'grep' '-r' 'some pattern' '/var/log'" is unambiguous.
func TestRunAgenticDiagnostics_SpaceArgShellQuoted(t *testing.T) {
	client := startTestSSHServer(t, func(_ string, ch ssh.Channel) {
		_, _ = io.WriteString(ch, "/var/log/app.log:error: out of memory\n")
		sendExitStatus(ch, 0)
	})

	runner := &capturingToolRunner{
		calls:  []agentToolCall{{name: "execute_command", input: `{"command": ["grep", "-r", "out of memory", "/var/log"]}`}},
		result: "memory analysis",
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
	// The argument with a space must be quoted so the prefix is unambiguous.
	if !strings.Contains(runner.toolOutputs[0], "'out of memory'") {
		t.Errorf("expected space-containing arg to be quoted in tool result, got: %q", runner.toolOutputs[0])
	}
	// Verify the full prefix format.
	if !strings.Contains(runner.toolOutputs[0], "$ 'grep' '-r' 'out of memory' '/var/log'") {
		t.Errorf("expected shell-quoted command prefix in tool result, got: %q", runner.toolOutputs[0])
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
		{"systemctl", "cat", "nginx.service"},
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

// TestParseCommandInput_TooManyElements verifies that an oversized argv is
// rejected before any work is done. An adversary (or hallucinating model)
// returning thousands of array elements could cause OOM in shellQuote and
// flood structured logs with multi-megabyte "command" fields.
func TestParseCommandInput_TooManyElements(t *testing.T) {
	// Build a command array with one more element than the limit.
	args := make([]string, maxArgvElements+1)
	for i := range args {
		args[i] = "ls"
	}
	data, _ := json.Marshal(map[string]any{"command": args})
	_, err := parseCommandInput(json.RawMessage(data))
	if err == nil {
		t.Fatalf("expected error for command with %d elements (limit %d)", len(args), maxArgvElements)
	}
	if !strings.Contains(err.Error(), "maximum") {
		t.Errorf("error should mention the maximum, got: %v", err)
	}
}

// TestParseCommandInput_ArgTooLong verifies that a single argument exceeding
// maxArgLen is rejected. An oversized argument would cause shellQuote to
// allocate a huge string and could flood log lines.
func TestParseCommandInput_ArgTooLong(t *testing.T) {
	oversized := strings.Repeat("A", maxArgLen+1)
	data, _ := json.Marshal(map[string]any{"command": []string{"cat", oversized}})
	_, err := parseCommandInput(json.RawMessage(data))
	if err == nil {
		t.Fatalf("expected error for argument of length %d (limit %d)", maxArgLen+1, maxArgLen)
	}
	if !strings.Contains(err.Error(), "maximum length") {
		t.Errorf("error should mention maximum length, got: %v", err)
	}
}

// TestParseCommandInput_ExactLimitsAccepted verifies that inputs right at the
// limits (not over) are accepted without error.
func TestParseCommandInput_ExactLimitsAccepted(t *testing.T) {
	// Exactly maxArgvElements elements, each exactly maxArgLen bytes.
	args := make([]string, maxArgvElements)
	for i := range args {
		if i == 0 {
			args[i] = "cat" // first element is the command name
		} else {
			args[i] = strings.Repeat("A", maxArgLen)
		}
	}
	data, _ := json.Marshal(map[string]any{"command": args})
	_, err := parseCommandInput(json.RawMessage(data))
	if err != nil {
		t.Fatalf("unexpected error for input at exact limits: %v", err)
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

// TestIsDenied_BlocksAwkInterpreter verifies that awk (and its common variants
// gawk, mawk) are denied by DefaultDeniedCommands. Like perl/python, awk is a
// scripting language that can bypass the command denylist via system("rm -rf /"),
// write files with print >"file", or pipe to denied commands with print|"cmd".
func TestIsDenied_BlocksAwkInterpreter(t *testing.T) {
	denied := [][]string{
		{"awk", "BEGIN { system(\"rm -rf /\") }"},
		{"awk", "-F:", "{print $1}", "/etc/passwd"},
		{"gawk", "BEGIN { system(\"reboot\") }"},
		{"mawk", "BEGIN { print \"evil\" > \"/etc/cron.d/backdoor\" }"},
		{"/usr/bin/awk", "BEGIN { system(\"shutdown now\") }"},
		{"/usr/bin/gawk", "BEGIN { print \"x\" | \"crontab -\" }"},
	}
	for _, argv := range denied {
		if !isDenied(DefaultDeniedCommands, argv) {
			t.Errorf("expected awk variant denied: %v", argv)
		}
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

// TestIsDenied_SedInPlaceBlocked verifies that sed with in-place flags is denied even
// when "sed" is not in the denylist. sed -i edits files on disk without shell
// redirection, making it as destructive as cp/mv for overwriting file content.
func TestIsDenied_SedInPlaceBlocked(t *testing.T) {
	denied := [][]string{
		{"sed", "-i", "s/foo/bar/", "/etc/hosts"},
		{"sed", "-i.bak", "s/foo/bar/", "/etc/hosts"},
		{"sed", "--in-place", "s/foo/bar/", "/etc/hosts"},
		{"sed", "--in-place=.bak", "s/foo/bar/", "/etc/hosts"},
		// Absolute path to sed must still trigger the in-place check.
		{"/usr/bin/sed", "-i", "s/x/y/", "/tmp/file"},
		// -i flag after the script (flag order should not matter).
		{"sed", "s/foo/bar/", "/etc/hosts", "-i"},
		// Combined short flags that include 'i' must also be caught.
		{"sed", "-ni", "s/foo/bar/", "/etc/hosts"},  // suppress output + in-place
		{"sed", "-Ei", "s/foo/bar/", "/etc/hosts"},  // extended regex + in-place
		{"sed", "-in", "s/foo/bar/", "/etc/hosts"},  // in-place + suppress (reversed order)
		{"/usr/bin/sed", "-ni", "s/x/y/", "/tmp/f"}, // absolute path + combined
	}
	for _, argv := range denied {
		if !isDenied(DefaultDeniedCommands, argv) {
			t.Errorf("expected sed in-place variant denied: %v", argv)
		}
	}
}

// TestIsDenied_SedReadOnlyAllowed verifies that sed without in-place flags is
// still allowed for diagnostic use (filtering log lines, extracting ranges, etc.).
func TestIsDenied_SedReadOnlyAllowed(t *testing.T) {
	allowed := [][]string{
		{"sed", "-n", "10,20p", "/var/log/syslog"},
		{"sed", "s/password=[^ ]*/password=[REDACTED]/g", "/var/log/app.log"},
		{"sed", "-n", "/ERROR/p", "/var/log/messages"},
		{"/usr/bin/sed", "-n", "1,50p", "/var/log/auth.log"},
	}
	for _, argv := range allowed {
		if isDenied(DefaultDeniedCommands, argv) {
			t.Errorf("expected read-only sed allowed: %v", argv)
		}
	}
}

// TestIsDenied_SedInPlaceAlwaysChecked verifies that sed -i is denied even when
// a custom denylist does not include "sed". This is the same defence-in-depth
// guarantee that applies to systemctl and find -exec.
func TestIsDenied_SedInPlaceAlwaysChecked(t *testing.T) {
	// Custom denylist that does NOT include "sed".
	custom := map[string]bool{"rm": true, "dd": true}

	denied := [][]string{
		{"sed", "-i", "s/foo/bar/", "/etc/hosts"},
		{"sed", "-i.bak", "s/x/y/", "/tmp/file"},
		{"sed", "--in-place", "s/a/b/", "/etc/resolv.conf"},
		{"sed", "--in-place=.orig", "s/a/b/", "/etc/resolv.conf"},
		{"sed", "-ni", "s/foo/bar/", "/etc/hosts"},
		{"sed", "-Ei", "s/foo/bar/", "/etc/hosts"},
	}
	for _, argv := range denied {
		if !isDenied(custom, argv) {
			t.Errorf("sed in-place not blocked with custom denylist: %v", argv)
		}
	}

	// Read-only sed must still be allowed with the custom denylist.
	allowed := [][]string{
		{"sed", "-n", "10,20p", "/var/log/syslog"},
		{"sed", "s/secret=.*/secret=[REDACTED]/", "/var/log/app.log"},
	}
	for _, argv := range allowed {
		if isDenied(custom, argv) {
			t.Errorf("read-only sed should be allowed with custom denylist: %v", argv)
		}
	}
}

// TestIsDenied_FindDeleteBlocked verifies that find with -delete, -fprint, or
// -fprint0 is denied even when "find" is not in the denylist. Unlike -exec,
// these flags act directly without spawning a sub-process:
//   - -delete removes each matched file/directory
//   - -fprint writes output to a named file (truncating first)
//   - -fprint0 same as -fprint with NUL separators
func TestIsDenied_FindDeleteBlocked(t *testing.T) {
	denied := [][]string{
		{"find", "/tmp", "-name", "*.tmp", "-delete"},
		{"find", "/var/log", "-mtime", "+30", "-delete"},
		{"/usr/bin/find", "/", "-name", "core", "-delete"},
		{"find", "/var/log", "-name", "*.log", "-fprint", "/tmp/logs.txt"},
		{"find", "/etc", "-type", "f", "-fprint0", "/tmp/files.txt"},
		// Flag appearing before the path expression should still be caught.
		{"find", "/", "-delete"},
	}
	for _, argv := range denied {
		if !isDenied(DefaultDeniedCommands, argv) {
			t.Errorf("expected find destructive flag denied: %v", argv)
		}
	}
}

// TestIsDenied_FindFprintfAndFlsBlocked verifies that find with -fprintf or -fls
// is denied even when "find" is not in the denylist. Both flags write output to
// an arbitrary file on the filesystem:
//   - -fprintf FILE FORMAT: writes printf-formatted output to FILE
//   - -fls FILE: writes long-format (-ls style) listing to FILE
//
// Like -fprint and -fprint0, these act directly without spawning a sub-process.
func TestIsDenied_FindFprintfAndFlsBlocked(t *testing.T) {
	// Both flags must be denied with the default denylist.
	denied := [][]string{
		{"find", "/var/log", "-name", "*.log", "-fprintf", "/tmp/out.txt", "%f\n"},
		{"find", "/etc", "-type", "f", "-fprintf", "/etc/cron.d/backdoor", "* * * * * id\n"},
		{"/usr/bin/find", "/", "-name", "core", "-fprintf", "/tmp/cores.txt", "%p\n"},
		{"find", "/var/log", "-name", "*.log", "-fls", "/tmp/listing.txt"},
		{"find", "/etc", "-type", "f", "-fls", "/tmp/etc.txt"},
		{"/usr/bin/find", "/", "-name", "*.conf", "-fls", "/tmp/conf.txt"},
	}
	for _, argv := range denied {
		if !isDenied(DefaultDeniedCommands, argv) {
			t.Errorf("expected find file-writing flag denied: %v", argv)
		}
	}

	// Same flags must be denied with a custom denylist that does NOT include "find".
	custom := map[string]bool{"rm": true, "dd": true}
	for _, argv := range denied {
		if !isDenied(custom, argv) {
			t.Errorf("find file-writing flag not blocked with custom denylist: %v", argv)
		}
	}
}

// TestIsDenied_FindDeleteAlwaysChecked verifies that find -delete is denied even
// when a custom denylist does not include "find". This is the same defence-in-
// depth guarantee that applies to -exec and sed -i.
func TestIsDenied_FindDeleteAlwaysChecked(t *testing.T) {
	// Custom denylist that does NOT include "find".
	custom := map[string]bool{"rm": true, "dd": true}

	denied := [][]string{
		{"find", "/tmp", "-name", "*.tmp", "-delete"},
		{"find", "/var/log", "-name", "*.log", "-fprint", "/tmp/out.txt"},
		{"find", "/etc", "-type", "f", "-fprint0", "/tmp/out.txt"},
	}
	for _, argv := range denied {
		if !isDenied(custom, argv) {
			t.Errorf("find destructive flag not blocked with custom denylist: %v", argv)
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
