package checkmk

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"

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

	// Port 1 on localhost is almost always closed; the dial should fail fast.
	_, err = d.Dial("closedhost", "127.0.0.1:1")
	if err == nil {
		t.Fatal("expected TCP dial error for port 1")
	}
}

// TestLimitedWriter_DiscardsBeyondLimit verifies that writes beyond the
// remaining capacity are silently discarded without returning an error, and
// that the returned n equals len(p) (the full slice length) even when the
// write is partially or fully discarded.
func TestLimitedWriter_DiscardsBeyondLimit(t *testing.T) {
	buf := new(bytes.Buffer)
	lw := &limitedWriter{w: buf, remaining: 5}

	// First write: fits within limit.
	n, err := lw.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 {
		t.Errorf("n = %d, want 5", n)
	}
	if buf.String() != "hello" {
		t.Errorf("buf = %q, want %q", buf.String(), "hello")
	}

	// Second write: limit already reached — full discard.
	n, err = lw.Write([]byte("world"))
	if err != nil {
		t.Fatalf("unexpected error on discard write: %v", err)
	}
	// Must pretend success (return full len) so the SSH package doesn't error.
	if n != 5 {
		t.Errorf("n = %d on discard, want 5", n)
	}
	// Buffer must not have grown.
	if buf.String() != "hello" {
		t.Errorf("buf = %q after discard, want %q", buf.String(), "hello")
	}
}

// TestLimitedWriter_PartialWrite verifies that when a write straddles the
// capacity limit only the bytes that fit are written, while the full slice
// length is still returned so callers don't see an error.
func TestLimitedWriter_PartialWrite(t *testing.T) {
	buf := new(bytes.Buffer)
	lw := &limitedWriter{w: buf, remaining: 3}

	// Write 5 bytes when only 3 remain → 3 written, 2 discarded.
	n, err := lw.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 {
		t.Errorf("n = %d, want 5 (full slice length)", n)
	}
	if buf.String() != "hel" {
		t.Errorf("buf = %q, want %q", buf.String(), "hel")
	}
	if lw.remaining != 0 {
		t.Errorf("remaining = %d, want 0 after partial write fills buffer", lw.remaining)
	}
}

// TestLimitedWriter_ZeroRemaining verifies that writing to an already-full
// limitedWriter returns len(p) without touching the underlying buffer.
func TestLimitedWriter_ZeroRemaining(t *testing.T) {
	buf := new(bytes.Buffer)
	lw := &limitedWriter{w: buf, remaining: 0}

	n, err := lw.Write([]byte("anything"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 8 {
		t.Errorf("n = %d, want 8", n)
	}
	if buf.Len() != 0 {
		t.Errorf("buf should remain empty, got %q", buf.String())
	}
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
