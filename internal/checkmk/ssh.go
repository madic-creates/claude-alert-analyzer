package checkmk

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func dialSSH(cfg Config, hostAddress string) (*ssh.Client, error) {
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

	sshCfg := &ssh.ClientConfig{
		User:            cfg.SSHUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCallback,
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

func runSSHCommand(client *ssh.Client, argv []string, timeout time.Duration) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("new session: %w", err)
	}
	defer session.Close()

	cmdStr := strings.Join(argv, " ")

	// Buffered channel so the goroutine can always send without blocking,
	// even when the timeout case is selected and the caller has returned.
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
	}
}
