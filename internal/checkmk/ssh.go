package checkmk

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type alertCategory int

const (
	categoryGeneric alertCategory = iota
	categoryCPU
	categoryDisk
	categoryMemory
	categoryService
)

type sshCommand struct {
	argv          []string
	truncateLines int
}

var serviceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_@.\-]+$`)

func validServiceName(name string) bool {
	return serviceNamePattern.MatchString(name) && len(name) <= 128
}

func detectCategory(serviceDesc, serviceOutput string) alertCategory {
	lower := strings.ToLower(serviceDesc + " " + serviceOutput)
	switch {
	case strings.Contains(lower, "cpu") || strings.Contains(lower, "load"):
		return categoryCPU
	case strings.Contains(lower, "disk") || strings.Contains(lower, "filesystem") || strings.Contains(lower, "mount"):
		return categoryDisk
	case strings.Contains(lower, "memory") || strings.Contains(lower, "swap") || strings.Contains(lower, "mem"):
		return categoryMemory
	case strings.Contains(lower, "systemd") || strings.Contains(lower, "service") || strings.Contains(lower, "process"):
		return categoryService
	default:
		return categoryGeneric
	}
}

func buildCommands(cat alertCategory, serviceName string) []sshCommand {
	cmds := []sshCommand{
		{argv: []string{"journalctl", "--no-pager", "-p", "err", "-n", "50", "--since", "1 hour ago"}},
	}

	switch cat {
	case categoryCPU:
		cmds = append(cmds,
			sshCommand{argv: []string{"top", "-bn1", "-o", "%CPU"}, truncateLines: 20},
			sshCommand{argv: []string{"uptime"}},
		)
	case categoryDisk:
		cmds = append(cmds,
			sshCommand{argv: []string{"df", "-h"}},
		)
	case categoryMemory:
		cmds = append(cmds,
			sshCommand{argv: []string{"free", "-h"}},
			sshCommand{argv: []string{"ps", "aux", "--sort=-%mem"}, truncateLines: 10},
		)
	case categoryService:
		if validServiceName(serviceName) {
			cmds = append(cmds,
				sshCommand{argv: []string{"systemctl", "status", serviceName}},
				sshCommand{argv: []string{"journalctl", "--no-pager", "-u", serviceName, "-n", "30"}},
			)
		} else {
			slog.Warn("invalid service name, skipping service commands", "name", serviceName)
		}
	}

	return cmds
}

func RunDiagnostics(ctx context.Context, cfg Config, hostname, serviceDesc, serviceOutput string, maxBytes int) string {
	cat := detectCategory(serviceDesc, serviceOutput)
	serviceName := extractServiceName(serviceDesc)
	cmds := buildCommands(cat, serviceName)

	client, err := dialSSH(cfg, hostname)
	if err != nil {
		return fmt.Sprintf("(SSH connection failed: %v)", err)
	}
	defer client.Close()

	var sections []string
	deadline := time.Now().Add(30 * time.Second)

	for _, cmd := range cmds {
		if time.Now().After(deadline) {
			sections = append(sections, "(timeout: remaining commands skipped)")
			break
		}

		cmdStr := strings.Join(cmd.argv, " ")
		output, err := runSSHCommand(client, cmd.argv, 10*time.Second)
		if err != nil {
			sections = append(sections, fmt.Sprintf("$ %s\n(error: %v)", cmdStr, err))
			continue
		}

		output = shared.RedactSecrets(output)
		if cmd.truncateLines > 0 {
			output = shared.TruncateLines(output, cmd.truncateLines)
		}
		output = shared.Truncate(output, maxBytes)

		sections = append(sections, fmt.Sprintf("$ %s\n%s", cmdStr, output))
	}

	return strings.Join(sections, "\n\n")
}

func extractServiceName(serviceDesc string) string {
	lower := strings.ToLower(serviceDesc)
	for _, prefix := range []string{"systemd ", "service "} {
		if strings.HasPrefix(lower, prefix) {
			return serviceDesc[len(prefix):]
		}
	}
	return serviceDesc
}

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

func runSSHCommand(client *ssh.Client, argv []string, timeout time.Duration) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("new session: %w", err)
	}
	defer session.Close()

	cmdStr := strings.Join(argv, " ")

	done := make(chan struct{})
	var output []byte
	var cmdErr error

	go func() {
		output, cmdErr = session.CombinedOutput(cmdStr)
		close(done)
	}()

	select {
	case <-done:
		return string(output), cmdErr
	case <-time.After(timeout):
		session.Close()
		return "", fmt.Errorf("timeout after %v", timeout)
	}
}
