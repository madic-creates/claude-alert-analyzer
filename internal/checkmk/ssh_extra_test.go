package checkmk

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// TestNewSSHDialer_ValidKeyAndKnownHosts verifies the happy path where both the
// SSH private key and the known_hosts file can be read and parsed successfully.
// Previously only the error paths were tested (missing files), leaving the
// constructor at 30% coverage.
func TestNewSSHDialer_ValidKeyAndKnownHosts(t *testing.T) {
	// Generate a throw-away ed25519 key pair.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Write the private key as a PEM file.
	privKeyPEM, err := marshalPrivateKeyPEM(priv)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}

	// Generate a host key to populate known_hosts.
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}

	// Write files to a temp directory.
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	khPath := filepath.Join(dir, "known_hosts")

	if err := os.WriteFile(keyPath, privKeyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	// known_hosts entry for a dummy host.
	khLine := knownhosts.Line([]string{"example.com"}, hostSigner.PublicKey())
	if err := os.WriteFile(khPath, []byte(khLine+"\n"), 0600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}

	cfg := Config{
		SSHKeyPath:        keyPath,
		SSHKnownHostsPath: khPath,
		SSHUser:           "monitor",
	}
	d, err := NewSSHDialer(cfg)
	if err != nil {
		t.Fatalf("NewSSHDialer: %v", err)
	}
	if d == nil {
		t.Fatal("NewSSHDialer returned nil dialer")
		return
	}
	if d.user != "monitor" {
		t.Errorf("user = %q, want %q", d.user, "monitor")
	}
	if d.signer == nil {
		t.Error("signer must not be nil")
	}
	if d.hostKeyCallback == nil {
		t.Error("hostKeyCallback must not be nil")
	}
}

// TestNewSSHDialer_BadKeyContent verifies that NewSSHDialer returns an error
// when the key file contains invalid PEM data.
func TestNewSSHDialer_BadKeyContent(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "bad_key")
	khPath := filepath.Join(dir, "known_hosts")

	// Write invalid key content.
	if err := os.WriteFile(keyPath, []byte("not a valid private key\n"), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	// known_hosts can be empty for this test.
	if err := os.WriteFile(khPath, []byte(""), 0600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}

	cfg := Config{SSHKeyPath: keyPath, SSHKnownHostsPath: khPath, SSHUser: "test"}
	_, err := NewSSHDialer(cfg)
	if err == nil {
		t.Fatal("expected error for invalid key content")
	}
}

// TestNewSSHDialer_MissingKnownHostsFile verifies that NewSSHDialer returns an
// error when the key file is valid but the known_hosts file does not exist.
func TestNewSSHDialer_MissingKnownHostsFile(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privKeyPEM, err := marshalPrivateKeyPEM(priv)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyPath, privKeyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	cfg := Config{
		SSHKeyPath:        keyPath,
		SSHKnownHostsPath: filepath.Join(dir, "nonexistent_known_hosts"),
		SSHUser:           "test",
	}
	_, err = NewSSHDialer(cfg)
	if err == nil {
		t.Fatal("expected error for missing known_hosts file")
	}
}

// TestSSHDialer_Dial_RefusedConnection verifies that SSHDialer.Dial returns a
// descriptive error when the TCP connection is refused. This exercises the
// previously-uncovered Dial method (0% coverage).
func TestSSHDialer_Dial_RefusedConnection(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privKeyPEM, err := marshalPrivateKeyPEM(priv)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}

	// Generate a dummy host key for known_hosts.
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	khPath := filepath.Join(dir, "known_hosts")

	if err := os.WriteFile(keyPath, privKeyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	khLine := knownhosts.Line([]string{"closedhost"}, hostSigner.PublicKey())
	if err := os.WriteFile(khPath, []byte(khLine+"\n"), 0600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}

	cfg := Config{SSHKeyPath: keyPath, SSHKnownHostsPath: khPath, SSHUser: "test"}
	d, err := NewSSHDialer(cfg)
	if err != nil {
		t.Fatalf("NewSSHDialer: %v", err)
	}

	// Dial expects a bare IP address; it always appends ":22" itself via
	// net.JoinHostPort. Port 22 is almost certainly not listening in a test
	// sandbox; even if it were, the remote host key would not match the dummy
	// key stored in known_hosts, so the SSH handshake would still fail.
	_, err = d.Dial(context.Background(), "closedhost", "127.0.0.1")
	if err == nil {
		t.Fatal("expected error when dialing an unreachable host")
	}
}

// TestSSHDialer_Dial_ContextCancelled verifies that SSHDialer.Dial returns an
// error immediately when the supplied context is already cancelled. Before this
// fix, Dial used net.DialTimeout which has no cancellation path; a cancelled
// worker context during graceful shutdown would block for the full 10-second
// TCP connect timeout before returning. With net.DialContext the dial unblocks
// as soon as the context is done.
func TestSSHDialer_Dial_ContextCancelled(t *testing.T) {
	d, err := buildTestDialer(t)
	if err != nil {
		t.Fatalf("buildTestDialer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel before dialing.

	_, err = d.Dial(ctx, "somehost", "127.0.0.1")
	if err == nil {
		t.Fatal("expected error for already-cancelled context, got nil")
	}
}

// TestSSHDialer_Dial_ConnectionUsableAfterHandshake is a regression test for a
// race between the watcher goroutine inside Dial and defer dialCancel(). Before
// the fix, defer dialCancel() fires between close(handshakeDone) and the
// function's return, making both channels ready simultaneously; Go's select
// then picks dialCtx.Done() at random ~50% of the time, closing the TCP
// connection underneath the returned *ssh.Client. The fix adds a non-blocking
// check of handshakeDone inside the dialCtx.Done() case: if handshakeDone is
// already closed, the connection belongs to the SSH client and must not be
// closed by the watcher goroutine.
func TestSSHDialer_Dial_ConnectionUsableAfterHandshake(t *testing.T) {
	const iters = 20
	for i := 0; i < iters; i++ {
		func() {
			_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("iter %d: generate host key: %v", i, err)
			}
			hostSigner, err := ssh.NewSignerFromKey(hostPriv)
			if err != nil {
				t.Fatalf("iter %d: host signer: %v", i, err)
			}
			serverCfg := &ssh.ServerConfig{NoClientAuth: true}
			serverCfg.AddHostKey(hostSigner)

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("iter %d: listen: %v", i, err)
			}
			defer ln.Close()

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
					if newChan.ChannelType() != "session" {
						_ = newChan.Reject(ssh.UnknownChannelType, "not needed")
						continue
					}
					ch, requests, err := newChan.Accept()
					if err != nil {
						return
					}
					go serveSession(ch, requests, func(_ string, ch ssh.Channel) {
						_, _ = io.WriteString(ch, "ok\n")
						sendExitStatus(ch, 0)
					})
				}
			}()

			port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
			d := &SSHDialer{
				user:            "test",
				signer:          mustBuildSigner(t),
				hostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec — test only
				sshPort:         port,
			}

			client, err := d.Dial(context.Background(), "127.0.0.1", "127.0.0.1")
			if err != nil {
				t.Fatalf("iter %d: Dial failed: %v", i, err)
			}
			defer client.Close()

			// Run a command to verify the connection is usable. Without the fix
			// the watcher goroutine may have closed the TCP connection after
			// defer dialCancel() ran, before the function returned to the caller.
			r := runSSHCommand(context.Background(), client, []string{"echo", "ok"}, 5*time.Second)
			if r.err != nil {
				t.Fatalf("iter %d: connection not usable after Dial returned: %v", i, r.err)
			}
			if !strings.Contains(r.output, "ok") {
				t.Errorf("iter %d: unexpected output: %q", i, r.output)
			}
		}()
	}
}

// mustBuildSigner generates a throw-away ed25519 signer for test use.
func mustBuildSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return signer
}

// marshalPrivateKeyPEM marshals an ed25519 private key into the OpenSSH PEM
// format understood by ssh.ParsePrivateKey.
func marshalPrivateKeyPEM(key ed25519.PrivateKey) ([]byte, error) {
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return pem.EncodeToMemory(block), nil
}
