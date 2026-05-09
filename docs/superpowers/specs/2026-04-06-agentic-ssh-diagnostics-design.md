# Agentic SSH Diagnostics for CheckMK Analyzer

**Date:** 2026-04-06
**Status:** Approved

## Summary

Replace the static, category-based SSH diagnostic commands with an agentic Claude tool-use loop. Claude freely chooses which commands to run on the alerted host via SSH (max 10 rounds), then produces the root-cause analysis directly. This replaces both the old `RunDiagnostics()` and the separate `AnalyzeWithClaude()` call for the checkmk-analyzer.

## Data Flow (new)

```
Webhook → Handler → Queue → Worker
  → GatherContext() [parallel]
      ├── Alert-Details (formatted string)
      └── CheckMK API: Host-Services
  → RunAgenticDiagnostics()
      ├── SSH connection
      ├── Claude Tool-Loop (max 10 rounds):
      │     User: Alert-Details + Host-Services
      │     Claude: tool_use(execute_command, ["df", "-h"])
      │     Tool-Result: filesystem output...
      │     Claude: tool_use(execute_command, ["du", "-sh", "/var/*"])
      │     Tool-Result: ...
      │     Claude: end_turn → Markdown analysis
      └── SSH connection close
  → PublishToNtfy(analysis)
```

Key change: the agentic loop produces the final analysis directly (option A from brainstorming). No separate `AnalyzeWithClaude()` call for checkmk.

## Design

### 1. Shared Tool-Use Types (`internal/shared/types.go`)

New types added alongside existing ones:

```go
type Tool struct {
    Name        string      `json:"name"`
    Description string      `json:"description"`
    InputSchema InputSchema `json:"input_schema"`
}

type InputSchema struct {
    Type       string              `json:"type"`
    Properties map[string]Property `json:"properties"`
    Required   []string            `json:"required"`
}

type Property struct {
    Type        string `json:"type"`
    Description string `json:"description"`
}

type ContentBlock struct {
    Type      string          `json:"type"`
    Text      string          `json:"text,omitempty"`
    ID        string          `json:"id,omitempty"`
    Name      string          `json:"name,omitempty"`
    Input     json.RawMessage `json:"input,omitempty"`
    ToolUseID string          `json:"tool_use_id,omitempty"`
    Content   string          `json:"content,omitempty"`
}
```

Changes to existing types:

- `ClaudeRequest`: add `Tools []Tool` field, `Messages` uses `[]ToolMessage` with `any` content (string or `[]ContentBlock`)
- `ClaudeResponse`: add `StopReason string`, `Content` becomes `[]ContentBlock`

### 2. Shared Multi-Turn Function (`internal/shared/claude.go`)

New function:

```go
func RunToolLoop(
    ctx context.Context,
    cfg BaseConfig,
    systemPrompt string,
    userPrompt string,
    tools []Tool,
    maxRounds int,
    handleTool func(name string, input json.RawMessage) (string, error),
) (string, error)
```

Behavior:
1. Build initial messages: `[{role: "user", content: userPrompt}]`
2. Send request with `tools` to Claude API
3. Check `stop_reason`:
   - `"end_turn"` → extract text blocks, return as result
   - `"tool_use"` → for each tool_use block: call `handleTool(name, input)`, build tool_result message
4. Append assistant response + tool results to messages
5. Repeat from step 2 (up to `maxRounds`)
6. After `maxRounds`: send one final request without tools so Claude produces a text summary

Internal refactoring: extract HTTP/auth logic from `AnalyzeWithClaude()` into a shared `sendRequest()` helper. `AnalyzeWithClaude()` remains unchanged in behavior (k8s-analyzer unaffected).

### 3. SSH Agentic Loop (`internal/checkmk/agent.go`)

New file containing:

**Tool definition:** Single tool `execute_command` with `command` parameter (string array).

**Command denylist:**
```go
var deniedCommands = map[string]bool{
    "rm": true, "rmdir": true, "dd": true, "mkfs": true,
    "shutdown": true, "reboot": true, "poweroff": true, "halt": true,
    "sudo": true, "su": true, "pkexec": true, "doas": true,
    "chmod": true, "chown": true, "chgrp": true,
    "kill": true, "killall": true, "pkill": true,
    "mv": true, "cp": true, "ln": true,
    "useradd": true, "userdel": true, "usermod": true,
    "passwd": true, "crontab": true,
    "iptables": true, "nft": true,
    "mount": true, "umount": true,
    "systemctl": true, // blocked by default, status/show allowed explicitly
}
```

`systemctl` is in the denylist but the tool handler explicitly allows `systemctl status <x>` and `systemctl show <x>` (read-only subcommands).

**Tool handler:** Parses command, checks denylist, executes via `runSSHCommand()`, applies `RedactSecrets()` and `Truncate()`.

**Main function:**
```go
func RunAgenticDiagnostics(
    ctx context.Context,
    cfg Config,
    claudeCfg shared.BaseConfig,
    hostname string,
    alertContext string,
    maxRounds int,
) (string, error)
```

1. Open SSH connection via `dialSSH()`
2. Build system prompt (SRE analyst role, read-only commands only, max rounds, markdown output under 500 words)
3. Call `shared.RunToolLoop()` with tool handler callback
4. Close SSH connection
5. Return analysis text

**System prompt content:**
- Role: Infrastructure SRE analyst investigating an alert via SSH
- Goal: Identify root cause, assess severity, suggest remediation
- Constraints: Read-only commands only, no privilege escalation, max 10 command rounds
- Output: Markdown analysis under 500 words, reference actual data from commands

### 4. Changes to Existing Files

**`internal/checkmk/ssh.go`:**
- Keep: `dialSSH()`, `runSSHCommand()`
- Remove: `RunDiagnostics()`, `buildCommands()`, `detectCategory()`, `extractServiceName()`, `alertCategory` type, `sshCommand` type, `validServiceName()`, `serviceNamePattern`

**`internal/checkmk/context.go`:**
- `GatherContext()` no longer produces an SSH diagnostics section
- Returns only Alert-Details + CheckMK-Services sections
- Host validation (CheckMK API check for hostname/host_address) moves to `RunAgenticDiagnostics()` or stays in context.go and is checked before calling the agentic loop

**`cmd/checkmk-analyzer/main.go`:**
- `processAlert()` changes from:
  `GatherContext() → AnalyzeWithClaude() → PublishToNtfy()`
  to:
  `GatherContext() → RunAgenticDiagnostics(formattedContext) → PublishToNtfy()`
- System prompt moves from main.go to agent.go
- No more `AnalyzeWithClaude()` call for checkmk

**`internal/checkmk/types.go`:**
- No changes. `shared.BaseConfig` passed separately.

### 5. Unchanged

- `cmd/k8s-analyzer/` — fully unchanged
- `internal/k8s/` — fully unchanged
- `internal/shared/ntfy.go` — unchanged
- `internal/shared/cooldown.go` — unchanged
- `internal/shared/redact.go` — unchanged

## Security

- **Denylist** for destructive commands (defense-in-depth)
- **systemctl** only with `status`/`show` subcommands
- **SSH exec** (argv form, no shell) — pipes/redirects/injection not possible
- **Unprivileged SSH user** (`nagios`) — OS-level access control
- **Secret redaction** on all command outputs before sending to Claude
- **Output truncation** per command to prevent excessive token usage
- **Host validation** via CheckMK API before SSH connection
- **known_hosts** enforcement (no TOFU)
- **Max 10 rounds** to bound cost and execution time

## File Change Summary

| File | Action |
|------|--------|
| `internal/shared/types.go` | Extend: tool-use types, ContentBlock, StopReason |
| `internal/shared/claude.go` | Extend: `RunToolLoop()`, extract `sendRequest()` |
| `internal/checkmk/agent.go` | **New**: denylist, tool handler, `RunAgenticDiagnostics()`, system prompt |
| `internal/checkmk/ssh.go` | Slim down: keep only `dialSSH()` + `runSSHCommand()` |
| `internal/checkmk/context.go` | Adapt: remove SSH section, return formatted context string |
| `cmd/checkmk-analyzer/main.go` | Adapt: `processAlert()` uses `RunAgenticDiagnostics()` |
