package checkmk

import (
	"encoding/json"
	"testing"
)

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
