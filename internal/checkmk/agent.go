package checkmk

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
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
- Common useful commands: journalctl, df, free, top, ps, ss, ip, lsblk, cat/tail/head on log files, systemctl status/show, du, lsof, netstat, find, iptables -L/-S/-n/-v or nft list ruleset/tables/chains (read-only firewall rules)

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
	"mv": true, "cp": true, "ln": true, "tee": true,
	"useradd": true, "userdel": true, "usermod": true, "groupadd": true, "groupdel": true,
	"passwd": true, "crontab": true,
	"iptables": true, "ip6tables": true, "nft": true,
	"mount": true, "umount": true,
	"mkswap": true, "swapon": true, "swapoff": true,
	"insmod": true, "rmmod": true, "modprobe": true,
	// truncate resizes or zeroes files (e.g. "truncate -s 0 /etc/passwd") and
	// can fill a disk with "truncate -s 100G /tmp/fill". shred overwrites file
	// content to prevent recovery — both are write operations that must be
	// blocked even though they are not shells or privilege-escalation tools.
	"truncate": true, "shred": true,
	"systemctl": true, // handled specially below
	// Shells and interpreters: deny to prevent denylist bypass via
	// "bash -c 'rm -rf /'", "python3 -c 'import os; os.system(...)'", etc.
	// Claude's system prompt already restricts it to read-only commands;
	// blocking these closes the gap for a hallucinatory or adversarial model.
	// tcsh/csh are the classic C shell family present on RHEL/CentOS, FreeBSD,
	// and many legacy Unix systems. ksh (Korn shell) and mksh (MirBSD Korn
	// shell) are standard on RHEL/CentOS (ksh93) and Debian/Ubuntu (mksh).
	// ash (Almquist shell) appears on Alpine containers as a separate binary
	// alongside the busybox sh symlink. All of these shells accept a -c flag
	// that executes an arbitrary command string, making them equivalent bypass
	// vectors to bash/sh. The versioned-variant heuristic automatically extends
	// the denial to versioned names (e.g. ksh93 → base "ksh" → denied).
	"bash": true, "sh": true, "dash": true, "zsh": true, "fish": true,
	"tcsh": true, "csh": true, "ksh": true, "mksh": true, "ash": true,
	"python": true, "python2": true, "python3": true,
	"perl": true, "ruby": true, "node": true, "nodejs": true,
	// env and xargs can be used to invoke denied commands as a sub-process.
	"env": true, "xargs": true,
	// awk is a scripting language present on every Linux host; it can bypass
	// the denylist via system("rm -rf /"), write files with print >"file",
	// or pipe to denied commands with print | "cmd". gawk/mawk/nawk are common
	// alternative implementations that must be denied for the same reason.
	// nawk ("one true awk") is the default on Alpine Linux and BSD systems.
	"awk": true, "gawk": true, "mawk": true, "nawk": true,
	// Lua, Tcl, and PHP scripting interpreters: all support system-call
	// primitives that can invoke denied commands as sub-processes.
	//   lua -e 'os.execute("rm -rf /")'      — Lua os.execute()
	//   tclsh → exec rm -rf /                 — Tcl exec built-in
	//   php -r 'system("reboot");'            — PHP system()
	// lua is used by nginx/OpenResty, embedded devices, and game servers.
	// tclsh is installed by default on many RHEL, Debian, and Ubuntu systems.
	// wish is the Tk-enabled Tcl shell; it shares the same exec primitive.
	// php is ubiquitous on web-application hosts (LAMP/LEMP stacks).
	// The versioned-variant heuristic automatically extends the denial to
	// lua5.4, tclsh8.6, php8.1, and similar versioned binary names once
	// the base name appears in the denylist.
	"lua": true, "tclsh": true, "wish": true, "php": true,
	// busybox is a multi-call binary that exposes almost every Unix utility
	// (including sh, rm, wget, nc) under a single executable. Running
	// "busybox rm -rf /" or "busybox sh -c '...'" completely bypasses the
	// per-command denylist because the denylist checks the executable name
	// ("busybox"), not the applet name passed as the first argument.
	// busybox is standard on Alpine-based containers and embedded Linux images.
	"busybox": true,
	// Network data-transfer tools: curl and wget can download and pipe payloads
	// to a shell, exfiltrate data to remote hosts, or fetch and execute scripts.
	// nc/ncat/netcat open raw TCP/UDP connections and can tunnel arbitrary data
	// in or out of the host, including spawning a remote shell.
	// socat is a more capable successor to nc: it can relay data between
	// arbitrary address types (TCP, UDP, Unix sockets, files, PTYs) and is
	// commonly used to spawn fully interactive reverse shells.
	"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true, "socat": true,
	// SSH and file-transfer clients: ssh can connect to arbitrary remote hosts,
	// enabling lateral movement or exfiltration of gathered diagnostic data to
	// an attacker-controlled server. scp/sftp transfer files over SSH in either
	// direction. rsync synchronises file trees over SSH or rsync protocol and can
	// push data to a remote host. ftp/lftp open plaintext sessions to arbitrary
	// servers. All are blocked because a hallucinating or adversarially-prompted
	// model could use them to exfiltrate /etc/shadow, SSH private keys, or other
	// secrets collected during the diagnostic session. Diagnostic SSH access is
	// provided through the controlled Dialer — direct ssh spawning is not needed.
	"ssh": true, "scp": true, "sftp": true, "rsync": true, "ftp": true, "lftp": true,
	// install copies files like cp but also sets ownership and permissions,
	// making it trivially easy to plant a setuid binary or overwrite system files.
	"install": true,
	// at and batch schedule one-shot commands for deferred execution outside
	// the current SSH session, allowing persistence after the session ends.
	"at": true, "batch": true,
	// Debuggers: gdb, lldb, and cgdb expose an interactive shell command
	// ("gdb -ex 'shell cmd'" / "lldb -o 'platform shell cmd'") that executes
	// an arbitrary child process — effectively the same bypass as
	// bash/python/env. gdbserver opens a TCP/Unix debug port that allows a
	// remote client to control process execution on the host, enabling
	// exfiltration and lateral movement without any local interaction.
	// valgrind is a memory-analysis framework that always executes a target
	// program as a child process ("valgrind /bin/sh -c '...'"), making it a
	// direct command wrapper equivalent to nohup or timeout.
	"gdb": true, "lldb": true, "cgdb": true, "gdbserver": true,
	"valgrind": true,
	// Process execution wrappers: these commands accept another command as an
	// argument and execute it as a child process, allowing any denied command
	// to run undetected. For example, "nohup rm -rf /" passes the isDenied
	// check (only argv[0] is checked) but still invokes the denied "rm".
	// All common wrappers present on standard Linux systems are blocked here.
	//
	// nohup/setsid: run commands immune to hangups / in a new session.
	// timeout/watch: run commands with a time limit or repeatedly.
	// nice/ionice: execute a command with adjusted scheduling priority.
	// flock: acquire a lock file then execute a command.
	// strace/ltrace: trace syscalls/library calls while executing a command.
	// script: record a terminal session; -c <cmd> executes an arbitrary command.
	// nsenter/unshare/chroot: enter or create namespaces / change root, then exec.
	// expect: automates interactive programs; can spawn arbitrary sub-processes.
	"nohup": true, "setsid": true,
	"timeout": true, "watch": true,
	"nice": true, "ionice": true,
	"flock":  true,
	"strace": true, "ltrace": true,
	"script":  true,
	"nsenter": true, "unshare": true, "chroot": true,
	"expect": true,
}

var systemctlReadOnly = map[string]bool{
	"status": true, "show": true, "is-active": true, "is-failed": true,
	"is-enabled": true, "list-units": true, "list-unit-files": true,
	"list-timers": true, "list-sockets": true, "list-dependencies": true,
	"cat": true, // shows installed unit file content; read-only and useful for config inspection
}

// iptablesReadOnlyOps are iptables(8)/ip6tables(8) operation flags that only
// read firewall state without modifying it. Commands using only these flags
// (plus modifier-only flags such as -n, -v, -t, --line-numbers) are allowed
// even when "iptables"/"ip6tables" is in the denylist.
var iptablesReadOnlyOps = map[string]bool{
	"-L": true, "--list": true, // list rules in the selected chain
	"-S": true, "--list-rules": true, // print rules in iptables-save format
	"-C": true, "--check": true, // check whether a rule exists (does not modify state)
	"-V": true, "--version": true,
	"-h": true, "--help": true,
}

// nftReadOnlySubcmds are nft(8) subcommands that only read firewall state
// without modifying it. "nft list ..." (e.g. list ruleset, list tables, list
// chains) is the only nft subcommand used for read-only firewall inspection.
// All other nft subcommands (add, delete, flush, replace, create, rename,
// import, export, monitor, describe) either modify firewall state or stream
// output indefinitely, so only "list" is permitted.
var nftReadOnlySubcmds = map[string]bool{
	"list": true,
}

// iptablesWriteOps are iptables(8)/ip6tables(8) operation flags that modify
// firewall state. Their presence in any argv causes the command to be denied
// even if a read-only operation flag also appears.
var iptablesWriteOps = map[string]bool{
	"-A": true, "--append": true,
	"-D": true, "--delete": true,
	"-I": true, "--insert": true,
	"-R": true, "--replace": true,
	"-F": true, "--flush": true,
	"-X": true, "--delete-chain": true,
	"-P": true, "--policy": true,
	"-E": true, "--rename-chain": true,
	"-N": true, "--new-chain": true,
	"-Z": true, "--zero": true,
}

// findDestructiveFlags are find(1) primary expressions that perform
// destructive or write operations without executing a sub-process.
// They must be blocked alongside the exec flags even when "find" itself
// is not in the denylist:
//
//   - -delete   removes each matched file/directory from the filesystem
//   - -fprint   writes output to a named file (truncating it first)
//   - -fprint0  same as -fprint but with NUL separators
//   - -fprintf  writes formatted output to a named file (like -fprint with printf format)
//   - -fls      writes long-format listing to a named file (like -fprint with -ls format)
//
// These differ from -exec/-execdir in that they act directly rather than
// spawning a child process, so they require their own block list entry.
var findDestructiveFlags = map[string]bool{
	"-delete":  true,
	"-fprint":  true,
	"-fprint0": true,
	"-fprintf": true,
	"-fls":     true,
}

// findExecFlags are find(1) primary expressions that execute a sub-process.
// They allow running arbitrary commands for each matched file and must be
// blocked even when "find" itself is not in the denylist — just as
// bash/python/env are blocked to prevent denylist bypass via a shell wrapper.
var findExecFlags = map[string]bool{
	"-exec":    true,
	"-execdir": true,
	"-ok":      true,
	"-okdir":   true,
}

func isDenied(denied map[string]bool, argv []string) bool {
	if len(argv) == 0 {
		return true
	}

	// Normalize to base name so absolute paths (/bin/rm) and relative paths
	// (./rm) are checked the same as bare names (rm). Trim surrounding
	// whitespace so that a model-generated argv[0] like " sed" or "rm "
	// cannot bypass the denylist by making the name not match any entry.
	// Lower-case so that a prompt-injection attack instructing Claude to use
	// "RM" or "/BIN/Rm" cannot bypass the denylist: all denylist entries and
	// the special-case switch branches ("systemctl", "find", "sed") are
	// lowercase, so a case-sensitive lookup would silently miss uppercase
	// variants on a hypothetical case-insensitive or mixed-case host.
	cmd := strings.ToLower(strings.TrimSpace(filepath.Base(argv[0])))

	// A whitespace-only argv[0] normalises to "" after TrimSpace. Deny it
	// unconditionally: there is no valid command with an empty name, and
	// allowing it would silently skip the denylist (denied[""] == false).
	if cmd == "" {
		return true
	}

	if len(denied) == 0 {
		return false
	}

	// Special case: iptables/ip6tables — allow read-only operations (-L, -S,
	// -C) even when the command is in the denylist. Any write operation flag
	// (-A, -F, -P, etc.) denies the command regardless of other flags.
	// A command with no recognisable operation flag is also denied (safe default).
	if (cmd == "iptables" || cmd == "ip6tables") && denied[cmd] {
		// iptables flags are case-sensitive (-L ≠ -l, -S ≠ -s, -F ≠ -f), so
		// do NOT lowercase them before lookup. Only argv[0] is lowercased (above)
		// to prevent "IPTABLES -L" from bypassing this guard via uppercase cmd.
		readOnly := false
		for _, arg := range argv[1:] {
			if iptablesWriteOps[arg] {
				return true // write operation present — deny
			}
			if iptablesReadOnlyOps[arg] {
				readOnly = true
			}
		}
		return !readOnly // deny if no read-only operation flag found
	}

	// Special case: nft with the read-only "list" subcommand is allowed even
	// when "nft" is in the denylist. nft(8) is the nftables control tool and
	// the modern replacement for iptables on Linux 3.13+ (default on
	// Debian/Ubuntu 21+, Fedora 34+, RHEL 8+). "nft list ..." only reads
	// firewall state; all other subcommands (add, delete, flush, etc.) modify
	// it. Global options (e.g. -n/--numeric, -j/--json) may appear before the
	// subcommand, so skip leading dash-prefixed arguments to find it, matching
	// the same pattern used for systemctl below.
	if cmd == "nft" && denied["nft"] {
		subcmd := ""
		for _, arg := range argv[1:] {
			if !strings.HasPrefix(arg, "-") {
				subcmd = arg
				break
			}
		}
		return !nftReadOnlySubcmds[strings.ToLower(subcmd)]
	}

	// Special case: systemctl with read-only subcommands is allowed.
	// Flags (e.g. --no-pager, --user) may appear before the subcommand,
	// so skip leading dash-prefixed arguments to find the actual subcommand.
	if cmd == "systemctl" {
		// Deny remote-host and container flags before checking the subcommand.
		// --host/-H connects to a remote system via SSH, enabling lateral
		// movement beyond the diagnosed host.
		// --machine/-M targets a local systemd-nspawn container rather than
		// the host itself, taking diagnostics out of scope.
		// The short-option-with-separate-value form (-H user@remote) is already
		// implicitly blocked: the subcommand loop below finds "user@remote" as
		// the subcommand, which is not in systemctlReadOnly. The
		// long-option-with-equals form (--host=user@remote) bypasses that check
		// because the arg starts with "--" and is skipped entirely, allowing the
		// real subcommand (e.g. "status") to be found and incorrectly permitted.
		// Checking both forms here closes that gap and makes the intent explicit.
		for _, arg := range argv[1:] {
			if arg == "--host" || arg == "-H" || strings.HasPrefix(arg, "--host=") ||
				arg == "--machine" || arg == "-M" || strings.HasPrefix(arg, "--machine=") {
				return true
			}
		}
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
		subcmd = strings.ToLower(subcmd)
		return !systemctlReadOnly[subcmd]
	}

	// Special case: find with -exec/-execdir/-ok/-okdir can run arbitrary
	// sub-processes for each matched file — effectively bypassing the denylist.
	// Additionally, -delete removes matched files and -fprint/-fprint0 write
	// output to arbitrary files — both are destructive without spawning a child.
	// Deny whenever any of those flags appear in the argument list, regardless
	// of whether "find" itself is in the denylist.
	if cmd == "find" {
		for _, arg := range argv[1:] {
			// Normalise to lowercase so that a prompt-injection attack using
			// "-EXEC" or "-DELETE" cannot bypass the flag checks. This mirrors
			// the lowercase normalisation applied to argv[0] (cmd) above and to
			// the systemctl subcommand. The maps use lowercase keys; without
			// this normalisation findExecFlags["-EXEC"] == false even though
			// "-exec" is blocked.
			lower := strings.ToLower(arg)
			if findExecFlags[lower] || findDestructiveFlags[lower] {
				return true
			}
		}
		return denied[cmd]
	}

	// Special case: sed with -i / -i<suffix> / --in-place / --in-place=<suffix>
	// edits files in-place without shell redirection, making it as destructive as
	// cp/mv for overwriting files. Deny whenever an in-place flag is present,
	// regardless of whether "sed" itself is in the denylist.
	// BSD sed (FreeBSD, macOS) uses uppercase -I instead of -i for in-place editing;
	// both forms are blocked so the guard holds on non-Linux hosts too.
	if cmd == "sed" {
		for _, arg := range argv[1:] {
			if len(arg) >= 2 && (arg[:2] == "-i" || arg[:2] == "-I") {
				return true // -i/-I or -i<backup-suffix>/-I<backup-suffix> (GNU/BSD)
			}
			if arg == "--in-place" || strings.HasPrefix(arg, "--in-place=") {
				return true
			}
			// Combined short flags that include 'i' (GNU) or 'I' (BSD) also enable
			// in-place editing, e.g. -ni (suppress + in-place) or -nI (BSD equivalent).
			if len(arg) >= 2 && arg[0] == '-' && arg[1] != '-' &&
				(strings.ContainsRune(arg[1:], 'i') || strings.ContainsRune(arg[1:], 'I')) {
				return true
			}
		}
		return denied[cmd]
	}

	// Block mkfs.TYPE filesystem-specific formatting tools (e.g. mkfs.ext4,
	// mkfs.btrfs, mkfs.xfs). These bypass the exact "mkfs" denylist entry
	// because the versioned-variant heuristic strips only trailing digits and
	// dots: TrimRight("mkfs.ext4","0123456789.") yields "mkfs.ext" — not
	// "mkfs" — so denied["mkfs"] is never matched by that path.
	// Only block when "mkfs" itself is denied to respect custom denylists.
	if strings.HasPrefix(cmd, "mkfs.") && len(cmd) > 5 && denied["mkfs"] {
		return true
	}

	// Block nc.TYPE netcat variants (e.g. nc.openbsd, nc.traditional).
	// Debian/Ubuntu install netcat as /bin/nc.openbsd or /bin/nc.traditional;
	// these package-suffix names contain letters after the dot, so the
	// versioned-variant TrimRight heuristic (which strips only digits/dots)
	// never reduces them to "nc". The exact-match check therefore misses them.
	// Guard with denied["nc"] to respect custom denylists.
	if strings.HasPrefix(cmd, "nc.") && len(cmd) > 3 && denied["nc"] {
		return true
	}

	// Block iptables-TYPE and ip6tables-TYPE firewall variants (e.g. iptables-legacy,
	// iptables-nft, iptables-restore, ip6tables-legacy, ip6tables-nft).
	// Debian/Ubuntu ship /sbin/iptables-legacy and /sbin/iptables-nft alongside the
	// /sbin/iptables symlink; all of these can modify firewall rules. The versioned-variant
	// heuristic only strips trailing digits, dots, and hyphens, so "iptables-legacy" is
	// never reduced to "iptables" (it ends with 'y', not a digit or dot). Guard with
	// denied["iptables"] / denied["ip6tables"] to respect custom denylists.
	// Exception: any variant ending in "-save" (iptables-save, iptables-legacy-save,
	// iptables-nft-save) only dumps rules to stdout and never modifies firewall state;
	// allow these the same way the plain "iptables -S" read-only flag path is allowed.
	if strings.HasPrefix(cmd, "iptables-") && len(cmd) > len("iptables-") && denied["iptables"] {
		if strings.HasSuffix(cmd, "-save") {
			return false // *-save variants only read rules; allow them
		}
		return true
	}
	if strings.HasPrefix(cmd, "ip6tables-") && len(cmd) > len("ip6tables-") && denied["ip6tables"] {
		if strings.HasSuffix(cmd, "-save") {
			return false // *-save variants only read rules; allow them
		}
		return true
	}

	// Deny versioned interpreter and tool variants (e.g. python3.11, ruby2.7,
	// perl5.36, node20, python-3.11, bash-5.1). Strip a trailing version suffix
	// (any combination of digits and dots, optionally preceded by a hyphen
	// separator) and check the resulting base name against the denylist.
	// This closes two gaps:
	//   "python3" (denylist) vs "python3.11" (not by exact name, functionally same)
	//   "python"  (denylist) vs "python-3.11" (hyphen-separated version, same gap)
	// TrimRight removes only the rightmost sequence of cutset characters, so:
	//   - "python3.11"  → digits/dots stripped → "python"  (denied → deny)
	//   - "python-3.11" → digits/dots stripped → "python-" → hyphen stripped → "python" (denied → deny)
	//   - "bash-5.1"    → digits/dots stripped → "bash-"   → hyphen stripped → "bash"   (denied → deny)
	//   - "md5sum"      → base "md5sum" (base == cmd, skipped → exact-match path)
	//   - "ip6tables"   → trailing 's' not stripped → base == cmd → exact-match path
	base := strings.TrimRight(cmd, "0123456789.")
	base = strings.TrimRight(base, "-") // also strip separator from hyphen-versioned names like python-3.11
	if base != cmd && base != "" && denied[base] {
		return true
	}

	return denied[cmd]
}

// denyReason returns a human-readable explanation for why argv was denied.
// For commands that are only partially restricted (systemctl, find, sed) it
// provides specific guidance so Claude can self-correct and try a permitted
// alternative instead of abandoning the diagnostic approach entirely.
// denied is the same map passed to isDenied so the versioned-variant message
// is only emitted when the base command is actually in the denylist.
func denyReason(denied map[string]bool, argv []string) string {
	if len(argv) == 0 {
		return "Command denied: empty command"
	}
	// Normalize to lowercase, matching the same logic in isDenied, so that the
	// switch cases ("systemctl", "find", "sed") fire consistently when argv[0]
	// used an unexpected capitalisation.
	cmd := strings.ToLower(strings.TrimSpace(filepath.Base(argv[0])))

	switch cmd {
	case "nft":
		// Find the first non-option argument as the subcommand, matching
		// the same logic used in isDenied so the message targets the real reason.
		subcmd := ""
		for _, arg := range argv[1:] {
			if !strings.HasPrefix(arg, "-") {
				subcmd = arg
				break
			}
		}
		if subcmd != "" {
			return fmt.Sprintf("Command denied: nft %s is not permitted; only the read-only %q subcommand is allowed (e.g. nft list ruleset, nft list tables, nft list chains)", subcmd, "list")
		}
		return "Command denied: nft requires a read-only subcommand; allowed subcommand: \"list\" (e.g. nft list ruleset)"

	case "iptables", "ip6tables":
		// iptables flags are case-sensitive — do not lowercase before lookup.
		allowed := []string{"-L/--list", "-S/--list-rules", "-C/--check"}
		for _, arg := range argv[1:] {
			if iptablesWriteOps[arg] {
				return fmt.Sprintf("Command denied: %s %s modifies firewall rules; only read-only operation flags are allowed (%s) plus modifier flags (-n, -v, -t <table>, --line-numbers)", cmd, arg, strings.Join(allowed, ", "))
			}
		}
		return fmt.Sprintf("Command denied: %s requires a read-only operation flag; allowed operation flags: %s (modifier flags such as -n, -v, -t <table>, --line-numbers are also permitted)", cmd, strings.Join(allowed, ", "))

	case "systemctl":
		// Check for remote/container flags before looking for the subcommand,
		// matching the same order as isDenied so the message targets the real
		// reason the command was blocked.
		for _, arg := range argv[1:] {
			if arg == "--host" || arg == "-H" || strings.HasPrefix(arg, "--host=") {
				return "Command denied: systemctl --host/-H targets a remote system via SSH; run diagnostic commands directly on the affected host instead"
			}
			if arg == "--machine" || arg == "-M" || strings.HasPrefix(arg, "--machine=") {
				return "Command denied: systemctl --machine/-M targets a container; connect to the container directly for container-level diagnostics"
			}
		}
		subcmd := ""
		for _, arg := range argv[1:] {
			if !strings.HasPrefix(arg, "-") {
				subcmd = arg
				break
			}
		}
		allowed := make([]string, 0, len(systemctlReadOnly))
		for sc := range systemctlReadOnly {
			allowed = append(allowed, sc)
		}
		sort.Strings(allowed)
		subcmd = strings.ToLower(subcmd)
		if subcmd != "" {
			return fmt.Sprintf("Command denied: systemctl %s is not permitted; only read-only subcommands are allowed: %s", subcmd, strings.Join(allowed, ", "))
		}
		return fmt.Sprintf("Command denied: systemctl requires a read-only subcommand; allowed subcommands: %s", strings.Join(allowed, ", "))

	case "find":
		for _, arg := range argv[1:] {
			// Normalise to lowercase to match the same normalisation in isDenied,
			// so that uppercase variants ("-EXEC", "-DELETE") produce the correct
			// targeted guidance rather than falling through to the generic message.
			lower := strings.ToLower(arg)
			if findExecFlags[lower] {
				return fmt.Sprintf("Command denied: find %s is not permitted (exec flags can spawn arbitrary sub-processes); omit %s and redirect output instead", arg, arg)
			}
			if findDestructiveFlags[lower] {
				return fmt.Sprintf("Command denied: find %s is not permitted (destructive flag); omit %s", arg, arg)
			}
		}

	case "sed":
		for _, arg := range argv[1:] {
			if len(arg) >= 2 && (arg[:2] == "-i" || arg[:2] == "-I") {
				return "Command denied: sed with -i/--in-place is not permitted; run sed without -i to write to stdout instead"
			}
			if arg == "--in-place" || strings.HasPrefix(arg, "--in-place=") {
				return "Command denied: sed with -i/--in-place is not permitted; run sed without -i to write to stdout instead"
			}
			if len(arg) >= 2 && arg[0] == '-' && arg[1] != '-' &&
				(strings.ContainsRune(arg[1:], 'i') || strings.ContainsRune(arg[1:], 'I')) {
				return "Command denied: sed with -i/--in-place is not permitted; run sed without -i to write to stdout instead"
			}
		}
		// sed is in the custom denylist without in-place flags — fall through to generic message.
	}

	// mkfs.TYPE filesystem-specific formatting tool (e.g. mkfs.ext4, mkfs.btrfs,
	// mkfs.xfs). isDenied blocks these when "mkfs" is in the denylist; give
	// Claude a specific message so it understands why and does not retry with
	// another mkfs variant.
	if strings.HasPrefix(cmd, "mkfs.") && len(cmd) > 5 && denied["mkfs"] {
		return fmt.Sprintf("Command denied: %q formats a filesystem and is blocked (variant of %q which is in the command denylist); use read-only diagnostic commands instead", cmd, "mkfs")
	}

	// nc.TYPE netcat variant (e.g. nc.openbsd, nc.traditional). isDenied blocks
	// these when "nc" is in the denylist; give Claude a specific message so it
	// understands why and does not retry with another netcat variant.
	if strings.HasPrefix(cmd, "nc.") && len(cmd) > 3 && denied["nc"] {
		return fmt.Sprintf("Command denied: %q is a netcat variant blocked as a variant of %q which is in the command denylist; use read-only diagnostic commands instead", cmd, "nc")
	}

	// iptables-TYPE / ip6tables-TYPE firewall variant (e.g. iptables-legacy, iptables-nft,
	// ip6tables-legacy). isDenied blocks these when "iptables"/"ip6tables" is in the denylist.
	// Give Claude a specific message so it understands why and does not retry with another variant.
	if strings.HasPrefix(cmd, "iptables-") && len(cmd) > len("iptables-") && denied["iptables"] {
		// *-save variants (iptables-save, iptables-legacy-save, iptables-nft-save) are
		// allowed (read-only) and would not reach denyReason.
		return fmt.Sprintf("Command denied: %q is a firewall variant of %q which is in the command denylist; use iptables -L/-S for read-only listing or iptables-save instead", cmd, "iptables")
	}
	if strings.HasPrefix(cmd, "ip6tables-") && len(cmd) > len("ip6tables-") && denied["ip6tables"] {
		// *-save variants (ip6tables-save, ip6tables-legacy-save, ip6tables-nft-save) are
		// allowed (read-only) and would not reach denyReason.
		return fmt.Sprintf("Command denied: %q is a firewall variant of %q which is in the command denylist; use ip6tables -L/-S for read-only listing or ip6tables-save instead", cmd, "ip6tables")
	}

	// Versioned interpreter or tool variant (e.g. python3.11, ruby2.7, node20,
	// python-3.11, bash-5.1, nc6). isDenied strips the trailing version suffix
	// (digits/dots and optional hyphen separator) to find the base name in the
	// denylist. Give Claude a specific message that names the base command so it
	// understands why the versioned name was blocked and can choose a direct
	// read-only diagnostic command instead of retrying with another variant.
	// Guard with denied[base] to match isDenied's logic: a command ending in
	// digits that is itself explicitly denied (but whose base is not) must get
	// the generic "not allowed" message, not a misleading "versioned variant of
	// X" message for a base command that is not denied.
	// The message intentionally omits a category label (e.g. "scripting
	// interpreter") because the denylist covers both interpreters (bash, python)
	// and non-interpreter tools (nc, curl, ssh). Calling nc6 a "scripting
	// interpreter" would be inaccurate; a generic description covers all cases.
	base := strings.TrimRight(cmd, "0123456789.")
	base = strings.TrimRight(base, "-") // mirror isDenied: also strip hyphen separator
	if base != cmd && base != "" && denied[base] {
		return fmt.Sprintf("Command denied: %q is a versioned variant of %q which is blocked by the command denylist; use direct read-only diagnostic commands instead", cmd, base)
	}

	return fmt.Sprintf("Command denied: %q is not allowed (destructive or privileged command)", cmd)
}

// maxArgvElements is the maximum number of elements accepted in the command
// array from a Claude tool call. A legitimate diagnostic command rarely needs
// more than a handful of arguments; an unbounded array could cause OOM in
// shellQuote and flood structured logs with multi-megabyte "command" fields.
const maxArgvElements = 64

// maxArgLen is the maximum byte length of a single argument in the command
// array. Arguments longer than this are almost certainly not a real command
// option; capping them prevents shellQuote from allocating huge strings.
const maxArgLen = 4096

// maxTotalArgBytes is the maximum combined byte length of all arguments in a
// single command. Per-element limits alone allow up to maxArgvElements *
// maxArgLen = 256 KB per invocation; a total cap closes that gap so that
// shellQuote and log fields stay bounded even when many arguments are near
// their individual limit. Real diagnostic commands (df -h, ps aux, cat
// /path/to/file) never approach this ceiling.
const maxTotalArgBytes = 16384

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
	if len(parsed.Command) > maxArgvElements {
		return nil, fmt.Errorf("command has %d elements, maximum is %d", len(parsed.Command), maxArgvElements)
	}
	totalBytes := 0
	for i, arg := range parsed.Command {
		if arg == "" {
			return nil, fmt.Errorf("argument %d is empty", i)
		}
		if strings.TrimSpace(arg) == "" {
			return nil, fmt.Errorf("argument %d is whitespace-only", i)
		}
		if len(arg) > maxArgLen {
			return nil, fmt.Errorf("argument %d exceeds maximum length of %d bytes", i, maxArgLen)
		}
		if strings.ContainsRune(arg, '\x00') {
			return nil, fmt.Errorf("argument %d contains null byte", i)
		}
		if strings.ContainsRune(arg, '\n') || strings.ContainsRune(arg, '\r') {
			return nil, fmt.Errorf("argument %d contains newline", i)
		}
		// Reject leading/trailing whitespace (spaces, tabs) that are not caught
		// by the newline check above. A leading space in an argument like " -i"
		// shifts byte positions and bypasses the sed -i denylist check that
		// inspects arg[:2] for "-i"/"-I": " -i"[:2] is " -", not "-i". The
		// newline check already closes this class of bypass for "\n-i"; this
		// guard ensures the same invariant holds for spaces and tabs. No
		// legitimate diagnostic command argument has surrounding whitespace.
		if strings.TrimSpace(arg) != arg {
			return nil, fmt.Errorf("argument %d has leading or trailing whitespace", i)
		}
		// Reject the full C0 control range (0x00–0x1f) and DEL (0x7f). No
		// legitimate diagnostic command argument contains any of these bytes.
		// The null-byte, newline, and carriage-return checks above already
		// reject 0x00, 0x0a, and 0x0d individually; keeping this check
		// unconditional for the entire C0/DEL range adds defense in depth —
		// if those earlier checks were ever reordered or removed, this loop
		// still closes the bypass. It also catches tab (0x09): TrimSpace
		// rejects leading/trailing tabs but not a tab embedded mid-argument,
		// so "-exec\t" would pass TrimSpace unchanged and silently defeat
		// exact-match denylist lookups (findExecFlags stores "-exec", not
		// "-exec\t").
		//
		// C1 Unicode control characters (U+0080–U+009F) are also rejected.
		// Although they are multi-byte in UTF-8, they are valid Unicode code
		// points and JSON decodes them transparently (e.g. "\u0080"). Appending
		// a C1 character to a flag name — e.g. "-exec\u0080" — produces a
		// string that defeats exact-match denylist lookups in isDenied because
		// the map stores "-exec", not "-exec\u0080". Blocking U+0080–U+009F
		// closes this bypass without affecting any legitimate command argument.
		for _, r := range arg {
			if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
				return nil, fmt.Errorf("argument %d contains control character 0x%02x", i, r)
			}
		}
		totalBytes += len(arg)
	}
	if totalBytes > maxTotalArgBytes {
		return nil, fmt.Errorf("command total size %d bytes exceeds maximum of %d bytes", totalBytes, maxTotalArgBytes)
	}
	return parsed.Command, nil
}

// RunAgenticDiagnostics opens an SSH connection to the host and runs a Claude tool-use
// loop where Claude freely chooses diagnostic commands. Returns the final analysis text.
// verifiedIP is the IP address confirmed by CheckMK; the TCP connection is made directly
// to this IP to prevent DNS hijacking while hostname is still presented to the
// known_hosts callback for key verification.
func RunAgenticDiagnostics(
	ctx context.Context,
	cfg Config,
	client shared.ToolLoopRunner,
	dialer Dialer,
	hostname string,
	verifiedIP string,
	alertContext string,
	maxRounds int,
) (string, error) {
	denied := cfg.SSHDeniedCommands
	if denied == nil {
		denied = DefaultDeniedCommands
	}

	slog.Info("starting agentic SSH diagnostics", "hostname", hostname, "verifiedIP", verifiedIP, "maxRounds", maxRounds, "deniedCommands", len(denied))

	sshClient, err := dialer.Dial(ctx, hostname, verifiedIP)
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
			slog.Warn("denied command", "hostname", hostname, "command", shellQuote(argv))
			return denyReason(denied, argv), nil
		}

		logCmd := shellQuote(argv)
		slog.Info("agentic SSH command", "hostname", hostname, "command", logCmd)

		output, err := runSSHCommand(ctx, sshClient, argv, 10*time.Second)
		if err != nil {
			slog.Warn("agentic SSH command failed", "hostname", hostname, "command", logCmd, "error", err)
			// If the command produced output before failing (e.g. non-zero exit
			// code from systemctl status, grep with no match, etc.), include it so
			// Claude can use the diagnostic information. Without this, "systemctl
			// status nginx" on a stopped service exits 3 and its full status output
			// is discarded, leaving Claude with only "Command failed: exit status 3".
			if output != "" {
				output = shared.SanitizeOutput(output)
				output = shared.RedactSecrets(output)
				output = shared.Truncate(output, 4096)
				return fmt.Sprintf("$ %s\n%s\n[exited: %v]", shellQuote(argv), output, err), nil
			}
			return fmt.Sprintf("Command failed: %v", err), nil
		}

		output = shared.SanitizeOutput(output)
		output = shared.RedactSecrets(output)
		output = shared.Truncate(output, 4096)

		return fmt.Sprintf("$ %s\n%s", shellQuote(argv), output), nil
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
