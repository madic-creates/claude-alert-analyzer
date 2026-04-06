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
		if !isDenied(argv) {
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
		if isDenied(argv) {
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
		if isDenied(argv) {
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
		if !isDenied(argv) {
			t.Errorf("expected denied: %v", argv)
		}
	}
}

func TestIsDenied_EmptyCommand(t *testing.T) {
	if !isDenied(nil) {
		t.Error("expected denied for nil")
	}
	if !isDenied([]string{}) {
		t.Error("expected denied for empty")
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
