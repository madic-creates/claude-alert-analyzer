# Security

## Both analyzers

- Non-root execution (UID 65534)
- Read-only root filesystem
- All Linux capabilities dropped
- Fail-closed webhook auth (missing/invalid token → rejected)
- All gathered output passes through a secret-redaction filter before being sent to Claude (passwords, tokens, API keys, PEM blocks, emails)
- Claude response tokens capped at 2048

## CheckMK analyzer (additional)

- **Host validation**: both `hostname` and `host_address` from the alert must match a known CheckMK host before any SSH connection is attempted
- **Strict SSH**: `known_hosts` mounted from a ConfigMap (no TOFU), key mounted as a volume (not via env var), no `ForwardAgent`
- **Command denylist**: destructive/privileged commands blocked (defense in depth on top of an unprivileged SSH user)
- **No shell**: commands run via SSH `exec` (argv), not through an interpreter
- **No privilege escalation**: SSH user is unprivileged; no `sudo`, `su`, `dmesg`, or `pkexec`

## Operational diagnostics (agentic loops)

Both analyzers drive an agentic Claude tool-loop capped at `MAX_AGENT_ROUNDS` (default 10) rounds per analysis. The checkmk-analyzer uses SSH; the k8s-analyzer uses `kubectl_exec` and `promql_query`.

**Allowed** — any read-only diagnostic command (`df`, `free`, `top`, `ps`, `journalctl`, `cat`/`tail`/`head` on logs, `ss`, `ip`, `du`, `lsblk`, `lsof`, `find`, `systemctl status/show`, …)

**Denied** — destructive / state-modifying commands, defined in [`DefaultDeniedCommands`](../internal/checkmk/agent.go). Configurable via `SSH_DENIED_COMMANDS`; set empty to disable all guardrails.

Command output is redacted and truncated per command before being sent to Claude.

## K8s analyzer — RBAC

The analyzer needs read access to cluster resources (events, pods, pod logs) — bind it to a ServiceAccount with a read-only ClusterRole. The agent enforces a verb allowlist (read-only built-ins only) and rejects identity-overriding flags before invoking `kubectl`, but RBAC is the authoritative gate — exclude `secrets` from the role to keep credentials out of reach.

Example manifests with the recommended ClusterRole live in [`deploy/k8s-analyzer/`](../deploy/k8s-analyzer/).
