package checkmk

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestNewSSHDialer_MissingKeyFile(t *testing.T) {
	cfg := Config{
		SSHKeyPath:        "/nonexistent/key",
		SSHKnownHostsPath: "/nonexistent/known_hosts",
		SSHUser:           "test",
	}
	_, err := NewSSHDialer(cfg)
	if err == nil {
		t.Error("expected error for missing key file")
	}
}

// startTestSSHServer starts a minimal in-process SSH server.
// handleExec is called with the command string and the open session channel;
// the handler is responsible for writing output and closing the channel.
func startTestSSHServer(t *testing.T, handleExec func(cmd string, ch ssh.Channel)) *ssh.Client {
	t.Helper()

	// Ephemeral host key
	_, hostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}

	// Ephemeral client key
	clientPub, clientKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	clientSigner, err := ssh.NewSignerFromKey(clientKey)
	if err != nil {
		t.Fatalf("client signer: %v", err)
	}
	authorizedKey, err := ssh.NewPublicKey(clientPub)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}

	serverCfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(authorizedKey.Marshal()) == string(key.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("unauthorized key")
		},
	}
	serverCfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		sshConn, chans, reqs, err := ssh.NewServerConn(conn, serverCfg)
		if err != nil {
			return
		}
		defer sshConn.Close()
		go ssh.DiscardRequests(reqs)

		for newChan := range chans {
			if newChan.ChannelType() != "session" {
				_ = newChan.Reject(ssh.UnknownChannelType, "unsupported")
				continue
			}
			ch, requests, err := newChan.Accept()
			if err != nil {
				return
			}
			go serveSession(ch, requests, handleExec)
		}
	}()

	clientCfg := &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientSigner)},
		HostKeyCallback: ssh.FixedHostKey(hostSigner.PublicKey()),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("dial test server: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

// serveSession handles one SSH session channel, dispatching exec requests to handleExec.
func serveSession(ch ssh.Channel, requests <-chan *ssh.Request, handleExec func(string, ssh.Channel)) {
	defer ch.Close()
	for req := range requests {
		if req.Type != "exec" {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			continue
		}
		if len(req.Payload) < 4 {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			return
		}
		cmdLen := binary.BigEndian.Uint32(req.Payload[:4])
		cmd := string(req.Payload[4 : 4+cmdLen])
		if req.WantReply {
			_ = req.Reply(true, nil)
		}
		handleExec(cmd, ch)
		return
	}
}

// sendExitStatus sends an SSH exit-status channel request with the given code.
func sendExitStatus(ch ssh.Channel, code uint32) {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, code)
	_, _ = ch.SendRequest("exit-status", false, payload)
}

func TestRunSSHCommand_Success(t *testing.T) {
	client := startTestSSHServer(t, func(_ string, ch ssh.Channel) {
		_, _ = io.WriteString(ch, "hello output\n")
		sendExitStatus(ch, 0)
	})

	out, err := runSSHCommand(context.Background(), client, []string{"echo", "hello"}, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "hello output\n" {
		t.Errorf("unexpected output: %q", out)
	}
}

func TestRunSSHCommand_CommandError(t *testing.T) {
	client := startTestSSHServer(t, func(_ string, ch ssh.Channel) {
		_, _ = io.WriteString(ch, "command not found\n")
		sendExitStatus(ch, 127)
	})

	// session.Run returns an *ssh.ExitError on non-zero exit status
	_, err := runSSHCommand(context.Background(), client, []string{"nonexistent"}, 5*time.Second)
	if err == nil {
		t.Fatal("expected error for non-zero exit status")
	}
}

// TestRunSSHCommand_OutputTruncatedAtLimit verifies that when a remote command
// produces more than maxSSHOutputBytes of output, the collected output is
// capped at the limit rather than allowing unbounded memory growth, and that
// a truncation notice is appended so callers know the output is incomplete.
func TestRunSSHCommand_OutputTruncatedAtLimit(t *testing.T) {
	// Write 2x the limit so we can be sure the cap fires.
	oversized := strings.Repeat("A", maxSSHOutputBytes*2)
	client := startTestSSHServer(t, func(_ string, ch ssh.Channel) {
		_, _ = io.WriteString(ch, oversized)
		sendExitStatus(ch, 0)
	})

	out, err := runSSHCommand(context.Background(), client, []string{"cat", "/large/file"}, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) == 0 {
		t.Error("expected some output to be collected before the limit")
	}
	if !strings.Contains(out, "[output truncated at") {
		t.Errorf("expected truncation notice in output, got %d bytes without notice", len(out))
	}
}

func TestRunSSHCommand_Timeout(t *testing.T) {
	client := startTestSSHServer(t, func(_ string, _ ssh.Channel) {
		// Simulate a slow command: hold the server-side channel open so
		// CombinedOutput on the client side blocks until our timeout fires.
		time.Sleep(10 * time.Second)
	})

	_, err := runSSHCommand(context.Background(), client, []string{"sleep", "100"}, 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Errorf("expected timeout error message, got: %v", err)
	}
}

func TestShellQuote(t *testing.T) {
	tests := []struct {
		name string
		argv []string
		want string
	}{
		{
			name: "normal args",
			argv: []string{"ls", "-la", "/tmp"},
			want: "'ls' '-la' '/tmp'",
		},
		{
			name: "embedded single quotes",
			argv: []string{"echo", "it's"},
			want: `'echo' 'it'\''s'`,
		},
		{
			name: "semicolons and pipes",
			argv: []string{"cat", "/etc/passwd; rm -rf /", "| grep root"},
			want: `'cat' '/etc/passwd; rm -rf /' '| grep root'`,
		},
		{
			name: "dollar and backticks",
			argv: []string{"echo", "$(whoami)", "`id`"},
			want: "'echo' '$(whoami)' '`id`'",
		},
		{
			name: "nil/empty slice",
			argv: nil,
			want: "",
		},
		{
			name: "empty string argument",
			argv: []string{"echo", ""},
			want: "'echo' ''",
		},
		{
			name: "multiple single quotes",
			argv: []string{"echo", "it's a 'test'"},
			want: `'echo' 'it'\''s a '\''test'\'''`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := shellQuote(tc.argv)
			if got != tc.want {
				t.Errorf("shellQuote(%q)\n  got:  %s\n  want: %s", tc.argv, got, tc.want)
			}
		})
	}
}

// TestRunSSHCommand_Timeout_PartialOutput verifies that when a command times out,
// any output already written by the remote process before the deadline is returned
// alongside the timeout error rather than being discarded. This allows the agentic
// loop to surface partial diagnostic output (e.g. the first N log lines from a slow
// journalctl call) instead of returning an opaque "Command failed: timeout" message.
func TestRunSSHCommand_Timeout_PartialOutput(t *testing.T) {
	client := startTestSSHServer(t, func(_ string, ch ssh.Channel) {
		// Write some output immediately, then hold the channel open so the
		// timeout fires before the command "completes".
		_, _ = io.WriteString(ch, "partial output line\n")
		time.Sleep(10 * time.Second)
	})

	out, err := runSSHCommand(context.Background(), client, []string{"slow-cmd"}, 100*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Errorf("expected timeout error, got: %v", err)
	}
	if !strings.Contains(out, "partial output line") {
		t.Errorf("expected partial output to be returned on timeout, got: %q", out)
	}
}

func TestRunSSHCommand_ContextCancelled(t *testing.T) {
	client := startTestSSHServer(t, func(_ string, _ ssh.Channel) {
		// Simulate a slow command that blocks until the context is cancelled.
		time.Sleep(10 * time.Second)
	})

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel immediately so the select fires the ctx.Done() case.
	cancel()

	_, err := runSSHCommand(ctx, client, []string{"sleep", "100"}, 30*time.Second)
	if err == nil {
		t.Fatal("expected error when context is cancelled")
	}
	if !strings.Contains(err.Error(), "context cancelled") {
		t.Errorf("expected 'context cancelled' error message, got: %v", err)
	}
}

// TestRunSSHCommand_NewSessionFails verifies that runSSHCommand returns a
// "new session: ..." error when the underlying SSH connection is closed before
// NewSession is called. This is a real production failure mode: in an agentic
// diagnostic loop, the SSH connection can drop between tool calls (e.g. due to
// a server restart or network interruption). Without this path, a closed
// connection would panic or return an opaque error; with it, the caller
// receives a clear "new session: ..." diagnostic it can log or surface.
// This covers ssh.go lines 146-148 which were previously untested.
func TestRunSSHCommand_NewSessionFails(t *testing.T) {
	client := startTestSSHServer(t, func(_ string, ch ssh.Channel) {
		sendExitStatus(ch, 0)
	})

	// Close the connection before issuing a command so that NewSession fails.
	client.Close()

	_, err := runSSHCommand(context.Background(), client, []string{"uptime"}, 5*time.Second)
	if err == nil {
		t.Fatal("expected error when SSH connection is closed, got nil")
	}
	if !strings.Contains(err.Error(), "new session") {
		t.Errorf("expected 'new session' in error message, got: %v", err)
	}
}

func TestRunSSHCommand_ShellMetacharsEscaped(t *testing.T) {
	// The test SSH server captures the raw command string that the client
	// sends. We verify that shell metacharacters in argv are properly
	// single-quoted so the remote shell cannot interpret them.
	tests := []struct {
		name string
		argv []string
	}{
		{
			name: "semicolon injection",
			argv: []string{"cat", "/tmp/safe; rm -rf /"},
		},
		{
			name: "command substitution with dollar-paren",
			argv: []string{"echo", "$(cat /etc/shadow)"},
		},
		{
			name: "backtick command substitution",
			argv: []string{"echo", "`id`"},
		},
		{
			name: "pipe injection",
			argv: []string{"ls", "| cat /etc/passwd"},
		},
		{
			name: "embedded single quotes with injection",
			argv: []string{"echo", "'; rm -rf / #"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var captured string
			client := startTestSSHServer(t, func(cmd string, ch ssh.Channel) {
				captured = cmd
				sendExitStatus(ch, 0)
			})

			_, _ = runSSHCommand(context.Background(), client, tc.argv, 5*time.Second)

			expected := shellQuote(tc.argv)
			if captured != expected {
				t.Errorf("server received unexpected command\n  got:  %s\n  want: %s", captured, expected)
			}

			// Every argument must be single-quoted in the transmitted command.
			for _, arg := range tc.argv {
				// The raw argument should NOT appear unquoted. It must be
				// surrounded by single quotes (with any embedded single
				// quotes escaped).
				if strings.Contains(captured, " "+arg+" ") {
					t.Errorf("argument %q appears unquoted in command: %s", arg, captured)
				}
			}
		})
	}
}
