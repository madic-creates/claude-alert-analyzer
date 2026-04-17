package checkmk

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Dialer opens SSH connections to remote hosts.
type Dialer interface {
	Dial(host string) (*ssh.Client, error)
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

// Dial opens an SSH connection to the given host.
func (d *SSHDialer) Dial(hostAddress string) (*ssh.Client, error) {
	sshCfg := &ssh.ClientConfig{
		User:            d.user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(d.signer)},
		HostKeyCallback: d.hostKeyCallback,
		Timeout:         10 * time.Second,
	}
	addr := net.JoinHostPort(hostAddress, "22")
	client, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		return nil, fmt.Errorf("SSH dial %s: %w", addr, err)
	}
	return client, nil
}

type sshResult struct {
	output string
	err    error
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

	// Buffered channel so the goroutine can always send without blocking,
	// even when the timeout or context-cancellation case is selected and
	// the caller has returned.
	done := make(chan sshResult, 1)

	go func() {
		out, cmdErr := session.CombinedOutput(cmdStr)
		done <- sshResult{string(out), cmdErr}
	}()

	select {
	case r := <-done:
		return r.output, r.err
	case <-time.After(timeout):
		session.Close()
		return "", fmt.Errorf("timeout after %v", timeout)
	case <-ctx.Done():
		session.Close()
		return "", fmt.Errorf("context cancelled: %w", ctx.Err())
	}
}
