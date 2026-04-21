package checkmk

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Dialer opens SSH connections to remote hosts.
// Dial connects to the host by dialing ip directly (preventing DNS hijacking)
// while presenting hostname to the known_hosts callback so that hostname-keyed
// entries in the known_hosts file continue to match. The context controls
// cancellation of the TCP dial, so a shutdown or deadline propagates cleanly
// instead of blocking for the full TCP connect timeout.
type Dialer interface {
	Dial(ctx context.Context, hostname, ip string) (*ssh.Client, error)
}

// SSHDialer caches the parsed SSH key and known_hosts callback.
type SSHDialer struct {
	signer          ssh.Signer
	hostKeyCallback ssh.HostKeyCallback
	user            string
}

// NewSSHDialer parses the SSH key and known_hosts file once at startup.
func NewSSHDialer(cfg Config) (*SSHDialer, error) {
	keyBytes, err := os.ReadFile(cfg.SSHKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read SSH key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse SSH key: %w", err)
	}
	hostKeyCallback, err := knownhosts.New(cfg.SSHKnownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts: %w", err)
	}
	return &SSHDialer{signer: signer, hostKeyCallback: hostKeyCallback, user: cfg.SSHUser}, nil
}

// Dial opens an SSH connection to ip:22 while presenting hostname to the
// known_hosts callback. This ensures the TCP connection goes to the
// CheckMK-verified IP address (preventing DNS hijacking) while still
// allowing known_hosts entries that are keyed by hostname to match.
// The ctx is forwarded to net.DialContext so that a cancelled context
// (e.g. during graceful shutdown) terminates the TCP dial immediately
// instead of blocking for the full connect timeout.
func (d *SSHDialer) Dial(ctx context.Context, hostname, ip string) (*ssh.Client, error) {
	const dialTimeout = 10 * time.Second
	sshCfg := &ssh.ClientConfig{
		User:            d.user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(d.signer)},
		HostKeyCallback: d.hostKeyCallback,
		Timeout:         dialTimeout,
	}
	// Establish the TCP connection directly to the verified IP so that no
	// DNS resolution can redirect us to a different host. DialContext is
	// used instead of DialTimeout so that a cancelled context terminates
	// the dial immediately rather than waiting for the full timeout.
	ipAddr := net.JoinHostPort(ip, "22")
	nd := &net.Dialer{Timeout: dialTimeout}
	conn, err := nd.DialContext(ctx, "tcp", ipAddr)
	if err != nil {
		return nil, fmt.Errorf("TCP dial %s: %w", ipAddr, err)
	}
	// Pass hostname (not ipAddr) as the addr argument to NewClientConn so
	// that the known_hosts callback receives the hostname as the key.
	// known_hosts entries are typically recorded by hostname; using the IP
	// here would cause verification to fail for hostname-keyed entries.
	hostnameAddr := net.JoinHostPort(hostname, "22")
	c, chans, reqs, err := ssh.NewClientConn(conn, hostnameAddr, sshCfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("SSH handshake with %s (ip %s): %w", hostname, ip, err)
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// maxSSHOutputBytes is the maximum number of bytes collected from combined
// stdout+stderr before the read is truncated. This prevents a command that
// streams large amounts of data from exhausting memory before the per-command
// truncation in agent.go (4 KiB) has a chance to run.
const maxSSHOutputBytes = 512 * 1024 // 512 KiB

// limitedWriter writes to w until remaining reaches zero, then silently
// discards further writes. It is safe for concurrent use (stdout and stderr
// may be written from different goroutines by the SSH package).
type limitedWriter struct {
	mu        sync.Mutex
	w         *bytes.Buffer
	remaining int
	truncated bool // set to true the first time data is discarded
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	if lw.remaining <= 0 {
		lw.truncated = true
		return len(p), nil // discard, but pretend success so the session doesn't error
	}
	n := len(p)
	if n > lw.remaining {
		p = p[:lw.remaining]
		lw.truncated = true // trailing bytes will be discarded after this write
	}
	written, err := lw.w.Write(p)
	lw.remaining -= written
	// Return the original length so callers (the SSH package) don't treat a
	// partial write as an error.
	return n, err
}

type sshResult struct {
	output    string
	err       error
	truncated bool
}

// shellQuote joins argv into a single string safe for remote shell
// interpretation. Each element is wrapped in single quotes, and any
// embedded single quotes are escaped using the '\'' idiom (end the
// current single-quoted string, insert an escaped single quote, and
// start a new single-quoted string).
func shellQuote(argv []string) string {
	quoted := make([]string, len(argv))
	for i, arg := range argv {
		quoted[i] = "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
	}
	return strings.Join(quoted, " ")
}

func runSSHCommand(ctx context.Context, client *ssh.Client, argv []string, timeout time.Duration) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("new session: %w", err)
	}
	defer session.Close()

	cmdStr := shellQuote(argv)

	// Collect stdout and stderr into a shared buffer capped at maxSSHOutputBytes.
	// Using a limitedWriter prevents a command that streams large amounts of data
	// (e.g. "cat /large/file") from exhausting memory before the 4 KiB truncation
	// in agent.go runs. Both pipes share the same buffer and limit so the cap
	// applies to the combined output, matching the behaviour of CombinedOutput.
	lw := &limitedWriter{w: new(bytes.Buffer), remaining: maxSSHOutputBytes}
	session.Stdout = lw
	session.Stderr = lw

	// Buffered channel so the goroutine can always send without blocking,
	// even when the timeout or context-cancellation case is selected and
	// the caller has returned.
	done := make(chan sshResult, 1)

	go func() {
		cmdErr := session.Run(cmdStr)
		lw.mu.Lock()
		out := lw.w.String()
		wasTruncated := lw.truncated
		lw.mu.Unlock()
		done <- sshResult{out, cmdErr, wasTruncated}
	}()

	// Use time.NewTimer instead of time.After so we can call Stop() when the
	// command completes normally. time.After leaks the underlying timer until
	// it fires; in an agentic loop that runs many short commands with a 10s
	// timeout, the leaked timers accumulate unnecessarily.
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case r := <-done:
		out := r.output
		if r.truncated {
			out += fmt.Sprintf("\n[output truncated at %d bytes]", maxSSHOutputBytes)
		}
		return out, r.err
	case <-timer.C:
		session.Close()
		return "", fmt.Errorf("timeout after %v", timeout)
	case <-ctx.Done():
		session.Close()
		return "", fmt.Errorf("context cancelled: %w", ctx.Err())
	}
}

// Ensure limitedWriter implements io.Writer (compile-time check).
var _ io.Writer = (*limitedWriter)(nil)
