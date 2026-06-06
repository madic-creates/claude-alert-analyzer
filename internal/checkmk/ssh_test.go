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

	r := runSSHCommand(context.Background(), client, []string{"echo", "hello"}, 5*time.Second)
	if r.err != nil {
		t.Fatalf("unexpected error: %v", r.err)
	}
	if r.exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", r.exitCode)
	}
	if r.output != "hello output\n" {
		t.Errorf("unexpected output: %q", r.output)
	}
}

// TestRunSSHCommand_NonZeroExitCode verifies that when the remote command exits
// with a non-zero status, sshResult.exitCode is populated and sshResult.err is
// nil. This separates "command ran but failed" from "SSH session broke".
func TestRunSSHCommand_NonZeroExitCode(t *testing.T) {
	client := startTestSSHServer(t, func(_ string, ch ssh.Channel) {
		_, _ = io.WriteString(ch, "command not found\n")
		sendExitStatus(ch, 127)
	})

	r := runSSHCommand(context.Background(), client, []string{"nonexistent"}, 5*time.Second)
	if r.err != nil {
		t.Errorf("expected nil err for non-zero exit, got: %v", r.err)
	}
	if r.exitCode != 127 {
		t.Errorf("exitCode = %d, want 127", r.exitCode)
	}
	if !strings.Contains(r.output, "command not found") {
		t.Errorf("output = %q, want to contain 'command not found'", r.output)
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

	r := runSSHCommand(context.Background(), client, []string{"cat", "/large/file"}, 5*time.Second)
	if r.err != nil {
		t.Fatalf("unexpected error: %v", r.err)
	}
	if len(r.output) == 0 {
		t.Error("expected some output to be collected before the limit")
	}
	if !strings.Contains(r.output, "[output truncated at") {
		t.Errorf("expected truncation notice in output, got %d bytes without notice", len(r.output))
	}
}

// TestRunSSHCommand_ExactLimitNotTruncated verifies the exact boundary of the
// LimitedWriter cap: when a remote command produces exactly maxSSHOutputBytes of
// output, all bytes are returned and no truncation notice is appended. Paired
// with TestRunSSHCommand_OutputTruncatedAtLimit (body > limit → truncation notice),
// this closes the mutation gap where the limit guard in LimitedWriter could shift
// by one byte and silently discard the last byte of on-the-wire output.
func TestRunSSHCommand_ExactLimitNotTruncated(t *testing.T) {
	exact := strings.Repeat("B", maxSSHOutputBytes)
	client := startTestSSHServer(t, func(_ string, ch ssh.Channel) {
		_, _ = io.WriteString(ch, exact)
		sendExitStatus(ch, 0)
	})

	r := runSSHCommand(context.Background(), client, []string{"cat", "/exact/file"}, 5*time.Second)
	if r.err != nil {
		t.Fatalf("unexpected error: %v", r.err)
	}
	if len(r.output) != maxSSHOutputBytes {
		t.Errorf("exact-limit output: got %d bytes, want %d (no truncation at exact limit)", len(r.output), maxSSHOutputBytes)
	}
	if strings.Contains(r.output, "[output truncated at") {
		t.Error("exact-limit output must not contain truncation notice")
	}
}

func TestRunSSHCommand_Timeout(t *testing.T) {
	client := startTestSSHServer(t, func(_ string, _ ssh.Channel) {
		// Simulate a slow command: hold the server-side channel open so
		// CombinedOutput on the client side blocks until our timeout fires.
		time.Sleep(10 * time.Second)
	})

	r := runSSHCommand(context.Background(), client, []string{"sleep", "100"}, 50*time.Millisecond)
	if r.err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(r.err.Error(), "timeout") {
		t.Errorf("expected timeout error message, got: %v", r.err)
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

	r := runSSHCommand(context.Background(), client, []string{"slow-cmd"}, 100*time.Millisecond)
	if r.err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(r.err.Error(), "timeout") {
		t.Errorf("expected timeout error, got: %v", r.err)
	}
	if !strings.Contains(r.output, "partial output line") {
		t.Errorf("expected partial output to be returned on timeout, got: %q", r.output)
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

	r := runSSHCommand(ctx, client, []string{"sleep", "100"}, 30*time.Second)
	if r.err == nil {
		t.Fatal("expected error when context is cancelled")
	}
	if !strings.Contains(r.err.Error(), "context cancelled") {
		t.Errorf("expected 'context cancelled' error message, got: %v", r.err)
	}
}

// TestRunSSHCommand_ContextCancelled_PartialOutput verifies that partial output
// already written by the remote process before context cancellation is returned
// alongside the error, mirroring the timer-timeout path that also preserves
// partial output. Without this, diagnostic data produced before the cancellation
// (e.g. the start of a long log dump) is silently discarded.
func TestRunSSHCommand_ContextCancelled_PartialOutput(t *testing.T) {
	outputWritten := make(chan struct{})
	client := startTestSSHServer(t, func(_ string, ch ssh.Channel) {
		_, _ = io.WriteString(ch, "partial context output\n")
		close(outputWritten)
		time.Sleep(10 * time.Second) // hold channel open so ctx.Done fires
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Wait until the server has written output, then cancel.
	go func() {
		<-outputWritten
		// Allow a moment for the SSH packet to arrive at the client and be
		// written into lw before the context is cancelled.
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	r := runSSHCommand(ctx, client, []string{"slow-cmd"}, 30*time.Second)
	if r.err == nil {
		t.Fatal("expected error when context is cancelled")
	}
	if !strings.Contains(r.err.Error(), "context cancelled") {
		t.Errorf("expected 'context cancelled' error message, got: %v", r.err)
	}
	if !strings.Contains(r.output, "partial context output") {
		t.Errorf("expected partial output to be returned on context cancellation, got: %q", r.output)
	}
}

// TestRunSSHCommand_Timeout_TruncationMarkerPreserved verifies that when a
// chatty command exceeds maxSSHOutputBytes AND times out, the returned output
// includes the "[output truncated at N bytes]" marker. Without preserving the
// truncated flag from lw.Snapshot() in the <-timer.C branch, operators and the
// agentic loop saw a 512 KiB output blob without any indication the stream was
// cut off by the buffer cap rather than by the timeout — making it impossible
// to tell whether re-running with a shorter command would have fit.
func TestRunSSHCommand_Timeout_TruncationMarkerPreserved(t *testing.T) {
	oversized := strings.Repeat("A", maxSSHOutputBytes*2)
	client := startTestSSHServer(t, func(_ string, ch ssh.Channel) {
		_, _ = io.WriteString(ch, oversized)
		// Hold the channel open so the timeout fires after the bytes land.
		time.Sleep(10 * time.Second)
	})

	r := runSSHCommand(context.Background(), client, []string{"flood"}, 200*time.Millisecond)
	if r.err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(r.err.Error(), "timeout") {
		t.Errorf("expected timeout error, got: %v", r.err)
	}
	if !strings.Contains(r.output, "[output truncated at") {
		t.Errorf("expected truncation marker in timeout output, got %d bytes without marker", len(r.output))
	}
}

// TestRunSSHCommand_ContextCancelled_TruncationMarkerPreserved mirrors the
// timeout-path coverage above for the ctx.Done() branch. Same regression:
// without preserving the truncated flag from lw.Snapshot() in the
// <-ctx.Done() branch, a cancelled command that had overflowed the 512 KiB
// cap returned 512 KiB of output silently.
func TestRunSSHCommand_ContextCancelled_TruncationMarkerPreserved(t *testing.T) {
	oversized := strings.Repeat("B", maxSSHOutputBytes*2)
	outputWritten := make(chan struct{})
	client := startTestSSHServer(t, func(_ string, ch ssh.Channel) {
		_, _ = io.WriteString(ch, oversized)
		close(outputWritten)
		time.Sleep(10 * time.Second)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		<-outputWritten
		// Allow the SSH packets to arrive at the client and be written into
		// lw before cancelling, otherwise we race the buffer fill.
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	r := runSSHCommand(ctx, client, []string{"flood"}, 30*time.Second)
	if r.err == nil {
		t.Fatal("expected error when context is cancelled")
	}
	if !strings.Contains(r.err.Error(), "context cancelled") {
		t.Errorf("expected 'context cancelled' error message, got: %v", r.err)
	}
	if !strings.Contains(r.output, "[output truncated at") {
		t.Errorf("expected truncation marker in cancelled output, got %d bytes without marker", len(r.output))
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

	r := runSSHCommand(context.Background(), client, []string{"uptime"}, 5*time.Second)
	if r.err == nil {
		t.Fatal("expected error when SSH connection is closed, got nil")
	}
	if !strings.Contains(r.err.Error(), "new session") {
		t.Errorf("expected 'new session' in error message, got: %v", r.err)
	}
}

// TestRunSSHCommand_BiasTowardResult verifies that when the result channel,
// the timer, and the context-cancellation channel are all ready at the moment
// the select runs, runSSHCommand returns the real result rather than a false
// timeout or ctx.Err() sentinel. Without the bias-drain blocks in the
// <-timer.C and <-ctx.Done() branches, Go's pseudo-random select would
// frequently return a spurious timeout/cancellation for a command that
// actually succeeded, misleading both operators and the agentic loop in
// agent.go. The hook deterministically stages the all-three-ready race
// across 100 iterations; (1/3)^100 ≈ 0, so without the fix at least one
// iteration would virtually always pick the wrong case.
// Mirrors the regression test for NotifyAggregator.Stop()'s bias drain.
func TestRunSSHCommand_BiasTowardResult(t *testing.T) {
	for iter := 0; iter < 100; iter++ {
		client := startTestSSHServer(t, func(_ string, ch ssh.Channel) {
			_, _ = io.WriteString(ch, "hello output\n")
			sendExitStatus(ch, 0)
		})
		ctx, cancel := context.WithCancel(context.Background())

		testHookBeforeRunSSHSelect = func() {
			testHookBeforeRunSSHSelect = nil
			// Wait long enough for: the SSH round-trip to complete on
			// localhost, the goroutine to receive the exit status, build
			// sshResult, and push it to the buffered `done` chan. 50ms is
			// orders of magnitude more than needed for a localhost SSH
			// session. After this sleep, done is ready. timer.C (1ms
			// timeout) is also ready. Cancelling now makes ctx.Done() ready
			// as well — all three cases satisfied when the select runs.
			time.Sleep(50 * time.Millisecond)
			cancel()
		}

		r := runSSHCommand(ctx, client, []string{"echo", "hello"}, time.Millisecond)
		testHookBeforeRunSSHSelect = nil
		cancel()

		if r.err != nil {
			t.Fatalf("iter=%d: expected success despite all-three-ready race, got err=%v", iter, r.err)
		}
		if r.exitCode != 0 {
			t.Errorf("iter=%d: exitCode=%d, want 0", iter, r.exitCode)
		}
		if !strings.Contains(r.output, "hello output") {
			t.Errorf("iter=%d: unexpected output: %q", iter, r.output)
		}
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

			_ = runSSHCommand(context.Background(), client, tc.argv, 5*time.Second)

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

// TestSSHDialer_HandshakeContextCancellation verifies that cancelling the
// parent context while the SSH handshake is stalled covers two paths in Dial:
//  1. The watcher goroutine's `case <-dialCtx.Done()` arm fires and closes
//     the underlying TCP connection, unblocking ssh.NewClientConn.
//  2. The `dialCtx.Err() != nil` branch returns the context error rather than
//     the raw handshake error, so callers see a meaningful deadline/cancel
//     message instead of an opaque "connection reset" or "EOF".
func TestSSHDialer_HandshakeContextCancellation(t *testing.T) {
	_, clientKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(clientKey)
	if err != nil {
		t.Fatalf("make signer: %v", err)
	}

	// A TCP listener that accepts connections but never sends an SSH banner,
	// causing ssh.NewClientConn to stall until the watcher goroutine closes
	// the connection when dialCtx is cancelled.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(5 * time.Second) // hold open until the watcher closes it
	}()

	d := &SSHDialer{
		signer:          signer,
		hostKeyCallback: ssh.InsecureIgnoreHostKey(),
		user:            "test",
		sshPort:         fmt.Sprintf("%d", ln.Addr().(*net.TCPAddr).Port),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err = d.Dial(ctx, "test-host", "127.0.0.1")
	if err == nil {
		t.Fatal("expected error when SSH handshake is cancelled by context expiry")
	}
	if !strings.Contains(err.Error(), "context") {
		t.Errorf("expected context error in message, got: %v", err)
	}
}

// TestSSHDialer_Dial_HostnameAddrUsesConfiguredPort verifies that when sshPort
// is set to a non-default value, the HostKeyCallback receives a hostnameAddr
// built with that port rather than the hardcoded "22". Before the fix,
// hostnameAddr was always net.JoinHostPort(hostname, "22") regardless of sshPort,
// so known_hosts entries keyed by [hostname]:port would never match.
func TestSSHDialer_Dial_HostnameAddrUsesConfiguredPort(t *testing.T) {
	hostPub, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	hostPubKey, err := ssh.NewPublicKey(hostPub)
	if err != nil {
		t.Fatalf("host pub key: %v", err)
	}

	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	clientSigner, err := ssh.NewSignerFromKey(clientPriv)
	if err != nil {
		t.Fatalf("client signer: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverCfg := &ssh.ServerConfig{NoClientAuth: true}
	serverCfg.AddHostKey(hostSigner)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		srvConn, chans, reqs, err := ssh.NewServerConn(conn, serverCfg)
		if err != nil {
			return
		}
		defer srvConn.Close()
		go ssh.DiscardRequests(reqs)
		for newChan := range chans {
			_ = newChan.Reject(ssh.UnknownChannelType, "not needed")
		}
	}()

	port := fmt.Sprintf("%d", ln.Addr().(*net.TCPAddr).Port)
	var capturedAddr string

	d := &SSHDialer{
		signer: clientSigner,
		hostKeyCallback: func(hostname string, _ net.Addr, key ssh.PublicKey) error {
			capturedAddr = hostname
			if string(key.Marshal()) != string(hostPubKey.Marshal()) {
				return fmt.Errorf("unexpected host key")
			}
			return nil
		},
		user:    "test",
		sshPort: port,
	}

	client, err := d.Dial(context.Background(), "myhost", "127.0.0.1")
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	client.Close()

	want := net.JoinHostPort("myhost", port)
	if capturedAddr != want {
		t.Errorf("HostKeyCallback addr = %q, want %q\n(hostnameAddr must use the configured port, not hardcoded 22)", capturedAddr, want)
	}
}
