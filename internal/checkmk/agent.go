package checkmk

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
)

// agentSystemPromptTemplate is the base template for the agentic SSH prompt.
// %d is replaced with the actual maxRounds value at call time so Claude's
// self-reported round budget always matches the real limit passed to RunToolLoop.
const agentSystemPromptTemplate = `You are an infrastructure SRE analyst investigating a monitoring alert via SSH.

Your task:
1. Use the execute_command tool to run diagnostic commands on the affected host
2. Analyze the outputs to identify the root cause
3. When you have enough information, stop calling tools and write your analysis

Guidelines:
- Only run read-only diagnostic commands (no modifications, no writes, no restarts)
- You have NO root/sudo access — never attempt privilege escalation
- Start broad (check logs, resource usage) then narrow down based on findings
- You have a maximum of %d command rounds — use them wisely
- Common useful commands: journalctl, df, free, top, ps, ss, ip, lsblk, cat/tail/head on log files, systemctl status/show, du, lsof, netstat, find

Output your final analysis in markdown (headings, bold, lists, code blocks — no tables):
1. Root cause (most likely explanation based on evidence)
2. Severity and blast radius (other affected services/hosts)
3. Remediation steps (concrete actions, no sudo)
4. Correlations between services if applicable

Reference actual values from command outputs. Keep response under 500 words.
Start directly with the analysis — no preamble, meta-commentary, or introductory sentences like "I have enough data" or "Let me analyze this".`

// agentSystemPromptForRounds returns the agent system prompt with the actual
// maxRounds value substituted so Claude's self-reported budget always matches
// the real limit enforced by RunToolLoop. When the operator changes
// MAX_AGENT_ROUNDS (e.g. to 5 or 15), the prompt reflects the actual value
// rather than a hardcoded "10".
func agentSystemPromptForRounds(maxRounds int) string {
	return fmt.Sprintf(agentSystemPromptTemplate, maxRounds)
}

// StaticAnalysisSystemPrompt is used when SSH is disabled or unavailable.
// Unlike the agentic prompt it does not mention tools or SSH — it instructs
// Claude to reason purely from the CheckMK service state and alert details.
const StaticAnalysisSystemPrompt = `You are an infrastructure SRE analyst investigating a monitoring alert.

You have been given CheckMK alert details and service state for the affected host.
SSH access is not available, so base your analysis entirely on the provided context.

Output your analysis in markdown (headings, bold, lists, code blocks — no tables):
1. Root cause (most likely explanation based on the alert and service data)
2. Severity and blast radius (other affected services/hosts)
3. Remediation steps (concrete actions an operator should take)
4. Correlations between services if applicable

Reference actual values from the provided context. Keep response under 500 words.
Start directly with the analysis — no preamble, meta-commentary, or introductory sentences.`

var sshTool = shared.Tool{
	Name:        "execute_command",
	Description: "Execute a diagnostic command on the remote host via SSH. The command is passed as an argv array (not interpreted by a shell). Only read-only commands are allowed.",
	InputSchema: shared.InputSchema{
		Type: "object",
		Properties: map[string]shared.Property{
			"command": {
				Type:        "array",
				Description: "Command and arguments as array, e.g. [\"df\", \"-h\"] or [\"journalctl\", \"--no-pager\", \"-n\", \"50\"]",
				Items:       &shared.Items{Type: "string"},
			},
		},
		Required: []string{"command"},
	},
}

// DefaultDeniedCommands is the default denylist used when SSH_DENIED_COMMANDS is not set.
var DefaultDeniedCommands = map[string]bool{
	"rm": true, "rmdir": true, "dd": true, "mkfs": true, "mke2fs": true,
	"shutdown": true, "reboot": true, "poweroff": true, "halt": true, "init": true,
	"sudo": true, "su": true, "pkexec": true, "doas": true,
	"chmod": true, "chown": true, "chgrp": true,
	"kill": true, "killall": true, "pkill": true,
	"mv": true, "cp": true, "ln": true,
	"useradd": true, "userdel": true, "usermod": true, "groupadd": true, "groupdel": true,
	"passwd": true, "crontab": true,
	"iptables": true, "ip6tables": true, "nft": true,
	"mount": true, "umount": true,
	"mkswap": true, "swapon": true, "swapoff": true,
	"insmod": true, "rmmod": true, "modprobe": true,
	"systemctl": true, // handled specially below
	// Shells and interpreters: deny to prevent denylist bypass via
	// "bash -c 'rm -rf /'", "python3 -c 'import os; os.system(...)'", etc.
	// Claude's system prompt already restricts it to read-only commands;
	// blocking these closes the gap for a hallucinatory or adversarial model.
	"bash": true, "sh": true, "dash": true, "zsh": true, "fish": true,
	"python": true, "python2": true, "python3": true,
	"perl": true, "ruby": true, "node": true, "nodejs": true,
	// env and xargs can be used to invoke denied commands as a sub-process.
	"env": true, "xargs": true,
}

var systemctlReadOnly = map[string]bool{
	"status": true, "show": true, "is-active": true, "is-failed": true,
	"is-enabled": true, "list-units": true, "list-unit-files": true,
	"list-timers": true, "list-sockets": true, "list-dependencies": true,
}

func isDenied(denied map[string]bool, argv []string) bool {
	if len(argv) == 0 {
		return true
	}

	if len(denied) == 0 {
		return false
	}

	// Normalize to base name so absolute paths (/bin/rm) and relative paths
	// (./rm) are checked the same as bare names (rm).
	cmd := filepath.Base(argv[0])

	// Special case: systemctl with read-only subcommands is allowed.
	// Flags (e.g. --no-pager, --user) may appear before the subcommand,
	// so skip leading dash-prefixed arguments to find the actual subcommand.
	if cmd == "systemctl" {
		subcmd := ""
		for _, arg := range argv[1:] {
			if !strings.HasPrefix(arg, "-") {
				subcmd = arg
				break
			}
		}
		if subcmd == "" {
			return true // no subcommand found — deny
		}
		return !systemctlReadOnly[subcmd]
	}

	return denied[cmd]
}

func parseCommandInput(input json.RawMessage) ([]string, error) {
	var parsed struct {
		Command []string `json:"command"`
	}
	if err := json.Unmarshal(input, &parsed); err != nil {
		return nil, fmt.Errorf("parse command input: %w", err)
	}
	if len(parsed.Command) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	return parsed.Command, nil
}

// RunAgenticDiagnostics opens an SSH connection to the host and runs a Claude tool-use
// loop where Claude freely chooses diagnostic commands. Returns the final analysis text.
func RunAgenticDiagnostics(
	ctx context.Context,
	cfg Config,
	client shared.ToolLoopRunner,
	dialer Dialer,
	hostname string,
	alertContext string,
	maxRounds int,
) (string, error) {
	denied := cfg.SSHDeniedCommands
	if denied == nil {
		denied = DefaultDeniedCommands
	}

	slog.Info("starting agentic SSH diagnostics", "hostname", hostname, "maxRounds", maxRounds, "deniedCommands", len(denied))

	sshClient, err := dialer.Dial(hostname)
	if err != nil {
		return "", fmt.Errorf("SSH connection failed: %w", err)
	}
	defer func() { _ = sshClient.Close() }()
	slog.Info("SSH connected for agentic diagnostics", "hostname", hostname)

	handleTool := func(name string, input json.RawMessage) (string, error) {
		if name != "execute_command" {
			return "", fmt.Errorf("unknown tool: %s", name)
		}

		argv, err := parseCommandInput(input)
		if err != nil {
			return "", err
		}

		if isDenied(denied, argv) {
			cmdStr := strings.Join(argv, " ")
			slog.Warn("denied command", "hostname", hostname, "command", cmdStr)
			return fmt.Sprintf("Command denied: %q is not allowed (destructive or privileged command)", argv[0]), nil
		}

		cmdStr := strings.Join(argv, " ")
		slog.Info("agentic SSH command", "hostname", hostname, "command", cmdStr)

		output, err := runSSHCommand(ctx, sshClient, argv, 10*time.Second)
		if err != nil {
			slog.Warn("agentic SSH command failed", "hostname", hostname, "command", cmdStr, "error", err)
			// If the command produced output before failing (e.g. non-zero exit
			// code from systemctl status, grep with no match, etc.), include it so
			// Claude can use the diagnostic information. Without this, "systemctl
			// status nginx" on a stopped service exits 3 and its full status output
			// is discarded, leaving Claude with only "Command failed: exit status 3".
			if output != "" {
				output = shared.RedactSecrets(output)
				output = shared.Truncate(output, 4096)
				return fmt.Sprintf("$ %s\n%s\n[exited: %v]", cmdStr, output, err), nil
			}
			return fmt.Sprintf("Command failed: %v", err), nil
		}

		output = shared.RedactSecrets(output)
		output = shared.Truncate(output, 4096)

		return fmt.Sprintf("$ %s\n%s", cmdStr, output), nil
	}

	analysis, err := client.RunToolLoop(
		ctx, agentSystemPromptForRounds(maxRounds), alertContext,
		[]shared.Tool{sshTool}, maxRounds, handleTool,
	)
	if err != nil {
		return "", fmt.Errorf("agentic loop failed: %w", err)
	}

	slog.Info("agentic diagnostics complete", "hostname", hostname)
	return analysis, nil
}
