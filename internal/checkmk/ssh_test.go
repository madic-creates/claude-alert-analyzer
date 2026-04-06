package checkmk

import "testing"

// SSH primitive tests are integration-level (require SSH server).
// Unit tests for command validation are in agent_test.go.

func TestDialSSH_MissingKeyFile(t *testing.T) {
	cfg := Config{
		SSHKeyPath:        "/nonexistent/key",
		SSHKnownHostsPath: "/nonexistent/known_hosts",
		SSHUser:           "test",
	}
	_, err := dialSSH(cfg, "localhost")
	if err == nil {
		t.Error("expected error for missing key file")
	}
}
