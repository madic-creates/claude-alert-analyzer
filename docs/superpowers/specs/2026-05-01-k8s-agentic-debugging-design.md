# Agentic Debugging for the k8s-analyzer

**Date:** 2026-05-01
**Status:** Approved

## Goal

Bring the k8s-analyzer to feature parity with the checkmk-analyzer's agentic
diagnostic capability. Today the k8s-analyzer issues a single
`Analyzer.Analyze()` call against statically gathered context; this design
introduces a multi-turn Claude tool-use loop that lets Claude freely issue
read-only `kubectl` and PromQL queries until it has enough evidence for a root
cause.

Security has four layers, in order of enforcement:

1. **Code-level verb allowlist** in `parseKubectlInput` — only read-only
   built-in subcommands (`get`, `describe`, `logs`, `top`, `events`, …)
   reach the subprocess. Plugin dispatch and locally executed subcommands
   (`config`, `kustomize`, `plugin`, …) are rejected.
2. **Code-level global-flag denylist** — flags that swap the cluster
   identity, target server, or auth credentials (`--kubeconfig`,
   `--server`, `--token`, `--as`, etc.) are rejected before verb lookup,
   so an allowed verb cannot be used with alternate credentials.
3. **Subprocess hardening** — kubectl is invoked at a fixed absolute path
   (no `$PATH` resolution) with a scrubbed environment (only `HOME` and
   `USER`, so `KUBECONFIG`/proxy/`LD_PRELOAD` cannot redirect auth or
   inject behavior). The in-cluster ServiceAccount token at
   `/var/run/secrets/kubernetes.io/serviceaccount/...` is the only auth
   path that survives.
4. **RBAC ClusterRole** bound to the ServiceAccount — the authoritative
   server-side enforcement of which resources the agent can read.

Layers 1–3 close the gaps the API server cannot see (local subcommands,
flag-injected alternate credentials, env-injected behavior). Layer 4 is
the single source of truth for everything that reaches the cluster.
The code-level layers stay short and reviewable — not CheckMK-style deep
denylists — because RBAC carries the weight.

## Non-Goals

- Remediation actions (delete pod, scale, rollout restart, etc.). Read-only
  diagnostics only; the operator runs remediation themselves.
- Cluster-specific assumptions (k3s, Longhorn, Traefik, Cilium). The system
  prompt is generic Kubernetes + Prometheus.
- Preserving the existing pod-log namespace allowlist (`ALLOWED_NAMESPACES`).
  RBAC takes over scope control end-to-end, including the static prefetch's
  pod-log fetch — i.e. the prefetch's behavior **does** change in this
  direction.

## Architecture

```
Webhook → Auth → Cooldown dedup → Work queue → ProcessAlert
  → GatherContext (static prefetch: Prometheus + Events + Pods + Logs, parallel)
  → assemble userPrompt = alertHeader + AnalysisContext.FormatForPrompt()
  → RunAgenticDiagnostics
      → ToolLoopRunner.RunToolLoop(systemPrompt, userPrompt,
                                    [kubectl_exec, promql_query],
                                    maxRounds, handleTool)
      → final analysis
  → ntfy publish
```

The static prefetch keeps its parallel pipeline (`GatherContext` → Prometheus
+ Events + Pods + Logs → `AnalysisContext`). Two changes:

1. The `AllowedNamespaces` filter on the prefetch's pod-log step is removed
   — RBAC controls what the ServiceAccount can read.
2. The result is no longer the entire user prompt by itself: the existing
   alert-header preamble (`alertname`, `status`, `severity`, `namespace`,
   `StartsAt`) that today's `ProcessAlert` builds in `internal/k8s/pipeline.go`
   is preserved and prepended to the `AnalysisContext`-formatted body. The
   combined string is what `RunAgenticDiagnostics` passes to `RunToolLoop` as
   the user prompt. This keeps the existing prompt-shape regression tests
   (`internal/k8s/pipeline_test.go`) valid.

From there Claude can issue `kubectl_exec` calls (allowed read-only verbs
that the ServiceAccount also permits server-side) and `promql_query` calls
(re-using the existing `PrometheusClient`) until it ends the turn or the
round budget is exhausted.

## Tools

### `kubectl_exec`

```json
{
  "name": "kubectl_exec",
  "description": "Run a read-only kubectl command. The command is passed as an argv array (no shell). Examples: [\"get\",\"pods\",\"-n\",\"monitoring\",\"-o\",\"wide\"], [\"describe\",\"pod\",\"prom-0\",\"-n\",\"monitoring\"], [\"logs\",\"pod-x\",\"-n\",\"db\",\"--tail=100\"], [\"top\",\"nodes\"].",
  "input_schema": {
    "type": "object",
    "properties": {
      "command": {
        "type": "array",
        "items": { "type": "string" },
        "description": "kubectl arguments as argv array, without the leading 'kubectl'"
      }
    },
    "required": ["command"]
  }
}
```

Handler behavior:
- `parseKubectlInput` validates the argv with the same limits as
  `parseCommandInput` in `internal/checkmk/agent.go`:
  `maxArgvElements=64`, `maxArgLen=4096`, `maxTotalArgBytes=16384`,
  empty/whitespace-only/null-byte/newline/control-character rejection.
- **Verb allowlist** (read-only built-in subcommands only; rejection happens
  before subprocess invocation):
  ```
  get, describe, logs, top, events, explain, version,
  api-resources, api-versions, cluster-info, auth, rollout
  ```
  - `auth` is allowed only with the `can-i` sub-verb (e.g.
    `auth can-i get pods`); `auth login`/`auth whoami` and other
    forms are rejected.
  - `rollout` is allowed only with the `history` sub-verb
    (`rollout history`); other rollout forms (`status`, `restart`,
    `pause`, `resume`, `undo`) are rejected.
  - The first non-flag argv element is the verb. Anything not in the list
    is rejected with a clear, Claude-readable error string telling it which
    verb to use instead.
  - Plugin dispatch (`kubectl-<plugin>`) and locally-executed subcommands
    that bypass the API server (`config`, `kustomize`, `plugin`,
    `completion`, `alpha`, `debug`, `attach`, `exec`, `cp`, `port-forward`,
    `proxy`, `wait`) are explicitly rejected even though most of those are
    already absent from the allowlist — listing them in the rejection
    table-test makes the intent reviewable.
- **Global-flag denylist** (rejected anywhere in argv, before the verb is
  even looked up):
  ```
  --kubeconfig, --server, --token, --token-file,
  --as, --as-group, --as-uid,
  --user, --cluster, --context,
  --certificate-authority,
  --client-certificate, --client-key,
  --insecure-skip-tls-verify,
  --password, --username,
  --tls-server-name,
  --cache-dir,
  -s              (kubectl short alias for --server)
  ```
  Both `--flag value` and `--flag=value` forms are matched. The single-dash
  `-s` is matched as an exact-token compare against `argv` (not a substring),
  so per-subcommand short flags whose name happens to start with `s` are
  unaffected. These flags can swap the ServiceAccount identity, target a
  different API server, or point to a kubeconfig containing an `exec`
  auth-plugin (which kubectl runs as a child binary on every API call) —
  any one of them defeats RBAC. They are rejected even with allowed verbs.
  Test coverage is mandatory: every entry has a positive rejection case +
  every variant form (long, short, equals).
- **Fixed kubectl path:** the subprocess invokes `/usr/local/bin/kubectl`
  literally, never the `kubectl` name resolved against `$PATH`. The
  `kubectlSubprocess` constructor accepts the path as a parameter
  (default `/usr/local/bin/kubectl`, matching the Dockerfile install
  location) so tests can substitute their own. `exec.LookPath` is **not**
  used — a path that exists in the running container is verified at
  startup with a single `os.Stat`, and a missing or non-executable binary
  is logged but does not abort startup (the static prefetch still works).
- **Scrubbed env:** `cmd.Env` is set explicitly (not inherited). The
  whitelist passed in: only the variables kubectl genuinely needs:
  ```
  HOME=<container HOME>            (kubectl writes to ~/.kube/cache by default)
  USER=<container USER>
  ```
  Everything else (`KUBECONFIG`, `KUBE_*`, `HTTP_PROXY`, `HTTPS_PROXY`,
  `NO_PROXY`, `PATH`, `LD_PRELOAD`, the rest) is dropped. The
  in-cluster ServiceAccount is picked up via `rest.InClusterConfig()`
  on the implicit `/var/run/secrets/kubernetes.io/serviceaccount/...`
  path, which kubectl reads when no `KUBECONFIG` and no `--kubeconfig`
  is set — this is the only auth path that survives.
- Subprocess: `exec.CommandContext(ctx, kubectlPath, argv...)` with a 10 s
  per-command timeout (mirrors checkmk's `runSSHCommand`). `cmd.Env` set
  to the whitelist above; `cmd.Dir` set to the container HOME.
- Output passes through `shared.SanitizeOutput` → `shared.RedactSecrets` →
  `shared.Truncate(4096)` (mirrors checkmk).
- Non-zero exit code: stdout, stderr, and the exit-status string are returned
  to Claude as the tool result, so RBAC `Forbidden` errors and "not found"
  responses are visible and Claude can self-correct.

### `promql_query`

```json
{
  "name": "promql_query",
  "description": "Run a PromQL query against Prometheus. Returns time-series results.",
  "input_schema": {
    "type": "object",
    "properties": {
      "query": {
        "type": "string",
        "description": "PromQL expression (e.g. 'rate(http_requests_total[5m])')"
      }
    },
    "required": ["query"]
  }
}
```

Handler behavior:
- `parsePromQLInput` validates length cap (4096 bytes) and rejects newlines /
  control characters in the query string.
- Calls into a new public `Query(ctx, queryStr) string` method on
  `PrometheusClient` that exposes the existing private `query` (the existing
  `GetMetrics(alert)` is alert-shaped, not arbitrary-query-shaped). To keep
  testability the agent depends on a small interface
  `PromQLQuerier { Query(ctx context.Context, query string) string }` that
  `*PrometheusClient` satisfies. Output already truncated to
  `maxPromResultLines=50` inside the existing implementation.
- Per-query budget: the handler wraps the call in
  `context.WithTimeout(ctx, 10*time.Second)`, mirroring `kubectl_exec`. This
  is the only cost-control measure — there is no PromQL parser or cardinality
  estimator. The 10 s ceiling is enough headroom for a curated home-cluster
  Prometheus to refuse expensive queries and return an error string Claude
  can self-correct from.

## System Prompt

```
You are a Kubernetes SRE analyst investigating a monitoring alert.

Your task:
1. Use kubectl_exec to run read-only kubectl commands and promql_query for
   Prometheus queries.
2. Investigate the alert across pods, deployments, events, logs, and metrics.
3. When you have enough information, stop calling tools and write your analysis.

Guidelines:
- Read-only commands only. Allowed kubectl verbs: get, describe, logs, top,
  events, explain, version, api-resources, api-versions, cluster-info,
  `auth can-i`, `rollout history`.
- NEVER use: delete, apply, create, edit, patch, replace, scale, the rest of
  rollout (status, restart, pause, resume, undo), cordon/drain/uncordon,
  exec, cp, port-forward, proxy, debug, attach.
- NEVER pass: `--kubeconfig`, `--server`, `--token`, `--as`, `--user`,
  `--cluster`, `--context`, `--certificate-authority`, `--client-*`,
  `--insecure-skip-tls-verify`, or any other flag that overrides the cluster
  identity or auth — they are rejected by the runtime.
- The ServiceAccount's RBAC permissions decide what is actually allowed; if a
  command fails with "Forbidden", do NOT retry — pick a different angle.
- You have a maximum of %d tool rounds.
- Static context (Prometheus metrics, recent events, pod status, pod logs) is
  already in the user message — start by reading it before issuing your first
  tool call.
- Begin broad (cluster-wide events, namespace overview) then narrow down based
  on findings.

Output your final analysis in markdown (headings, bold, lists, code blocks —
no tables):
1. Root cause
2. Severity and blast radius
3. Remediation steps (concrete kubectl commands the operator should run)
4. Correlations between alerts/services if applicable

Reference actual values from command outputs and metric results. Keep response
under 500 words. Start directly with the analysis — no preamble,
meta-commentary, or introductory sentences.
```

The `%d` is replaced with the actual `MaxAgentRounds` value at call time so
Claude's self-reported budget always matches the real limit, exactly as in
`agentSystemPromptForRounds` for checkmk.

Read-only enforcement is the layered model described in **Goal**: system
prompt → verb allowlist → global-flag denylist → subprocess hardening →
RBAC ClusterRole. The system prompt is informational — the four code/cluster
layers below it do the actual enforcement.

## Code Changes

### New: `internal/k8s/agent.go`

- `agentSystemPromptTemplate` constant + `agentSystemPromptForRounds(maxRounds int)`.
- `kubectlTool`, `promqlTool` (`shared.Tool` definitions).
- `parseKubectlInput(json.RawMessage) ([]string, error)` — argv validation
  using the same constants as checkmk's `parseCommandInput`, **plus** two
  enforcement layers (see Tools section):
  1. **Global-flag denylist scan** runs first across the entire argv.
     Any banned auth/config flag (in either `--flag value` or `--flag=value`
     form) causes immediate rejection with a Claude-readable error string
     naming the offending flag and explaining why ("Command denied:
     `--kubeconfig` is not permitted; the in-cluster ServiceAccount is the
     only allowed identity").
  2. **Verb-allowlist check** finds the first non-flag token, looks it up
     in `allowedKubectlVerbs map[string]bool`, and for `auth` / `rollout`
     verifies the second non-flag token against a verb→sub-verb map
     (`auth`→{`can-i`}, `rollout`→{`history`}). Anything not allowed
     returns "Command denied: kubectl <verb> is not permitted; allowed
     verbs: …".
- `parsePromQLInput(json.RawMessage) (string, error)` — query length cap +
  newline / control-character rejection.
- `KubectlRunner` interface:
  ```go
  type KubectlRunner interface {
      Exec(ctx context.Context, argv []string, timeout time.Duration) (string, error)
  }
  ```
  Allows tests to mock subprocess execution.
- `kubectlSubprocess struct { Path string; Env []string }` — default
  implementation:
  - `Path` defaults to `/usr/local/bin/kubectl` (literal absolute path,
    never `LookPath`).
  - `Env` defaults to a fixed two-entry slice — `HOME=<runtime HOME>`
    and `USER=<runtime USER>` (read once at construction time from
    `os.Getenv`). All other environment is dropped.
  - `Exec` runs `exec.CommandContext(ctx, s.Path, argv...)` with
    `cmd.Env = s.Env` and `cmd.Dir = $HOME`. Returns combined
    stdout+stderr.
  - Constructor `NewKubectlSubprocess() *kubectlSubprocess` performs an
    `os.Stat` on `Path` at startup and logs a single warn-level message
    if missing or non-executable; it does not fail startup so the static
    prefetch (which uses client-go) keeps working.
- `RunAgenticDiagnostics(ctx context.Context, runner shared.ToolLoopRunner, kc KubectlRunner, prom PromQLQuerier, userPrompt string, maxRounds int) (string, error)`
  orchestrates the tool loop and dispatches tool calls to `KubectlRunner` or
  the PromQL handler. `userPrompt` is the full prompt body (alert header +
  formatted `AnalysisContext`), assembled by the caller in `pipeline.go`,
  not just the `AnalysisContext.FormatForPrompt()` output.
- Per-tool structured logging: every tool invocation emits a single
  `slog.Info` log with fields `{tool, argv (or query), duration_ms,
  outcome}` where `outcome` is one of `ok | rejected_validation |
  rejected_verb | exec_error | nonzero_exit | timeout`. The same outcome
  set is recorded as Prometheus labels (see metrics below).

### New: `internal/k8s/agent_test.go`

- `parseKubectlInput` table tests — empty argv, oversized argv,
  oversized arg, oversized total, null byte, newline, leading/trailing
  whitespace, C0/C1 control characters.
- `parseKubectlInput` verb-allowlist tests — every allowed verb passes;
  every explicitly-rejected verb (`config`, `kustomize`, `plugin`,
  `completion`, `alpha`, `debug`, `attach`, `exec`, `cp`, `port-forward`,
  `proxy`, `wait`, `delete`, `apply`, `create`, `edit`, `patch`,
  `replace`, `scale`, `cordon`, `drain`, `uncordon`) is rejected with a
  message containing the verb; sub-verb rules tested for `auth`
  (`can-i` allowed, `whoami` rejected) and `rollout` (`history` allowed,
  `restart`/`status`/`undo` rejected); `kubectl-<plugin>` dispatch
  attempted via argv `["kubectl-foo", ...]` rejected (the verb-lookup
  is on argv[0]; the wrapper script never reaches the plugin path).
- `parseKubectlInput` global-flag denylist tests — every banned flag
  (`--kubeconfig`, `--server`, `--token`, `--token-file`, `--as`,
  `--as-group`, `--as-uid`, `--user`, `--cluster`, `--context`,
  `--certificate-authority`, `--client-certificate`, `--client-key`,
  `--insecure-skip-tls-verify`, `--password`, `--username`,
  `--tls-server-name`, `--cache-dir`) is rejected in **both forms**
  — `["get", "pods", "--kubeconfig", "/x.yaml"]` and
  `["get", "pods", "--kubeconfig=/x.yaml"]`. Variant ordering tested:
  flag before verb (`["--kubeconfig=/x", "get", "pods"]`) and after.
- `parsePromQLInput` table tests — empty, length cap, embedded newlines,
  valid query.
- `kubectlSubprocess` test using the standard
  `os.Args[0] -test.run=TestHelperProcess` pattern. The helper-process
  binary inspects:
  - argv pass-through (matches the input array exactly).
  - timeout enforcement (sleeps past the deadline → context-cancel kills
    the child, returns a `timeout` outcome).
  - combined stdout+stderr capture.
  - **env isolation:** the helper checks `os.Environ()` and asserts that
    only `HOME` and `USER` are present, no `KUBECONFIG`, no `PATH`, no
    other variables.
  - **fixed-path execution:** test substitutes `Path` with the helper
    binary path; default `/usr/local/bin/kubectl` is verified by stat'ing
    the constructor's `Path` field, not by exec'ing it.
- `RunAgenticDiagnostics` tests with mocked `ToolLoopRunner`, mocked
  `KubectlRunner`, mocked PromQL — coverage for:
  - Single-tool round → end_turn happy path.
  - Multiple tool calls in one round (parallel `tool_use` blocks);
    verifies dispatcher returns one `tool_result` per call.
  - Forced-summary path: `RunToolLoop` exhausts `maxRounds` and Claude
    returns final text in a forced-summary turn.
  - Tool-handler panic recovery: a deliberate panic in the kubectl
    handler is caught by the wrapper and returned as a tool-result
    string; the loop continues.
  - Missing-`kubectl` binary: substitute `Path` with a non-existent
    path → `exec.CommandContext` returns `ENOENT` → outcome
    `exec_error`, error string visible to Claude, loop continues.
  - Per-tool structured-log assertions (outcome label matches expectation
    for ok / rejected_verb / nonzero_exit / timeout).

### Modified: `internal/k8s/types.go` (Config)

- Add `MaxAgentRounds int` (default 10, env `MAX_AGENT_ROUNDS` — same name
  as checkmk).
- Remove `AllowedNamespaces []string`.
- `MaxLogBytes` unchanged — still used by static prefetch's `getPodLogs`.

### Modified: `internal/k8s/context.go`

- Remove `isNamespaceAllowed`.
- `getPodLogs`: drop the allowlist check; the function runs unconditionally.
  RBAC controls which namespaces the ServiceAccount can read.

### Modified: `internal/k8s/pipeline.go`

- `PipelineDeps` gains:
  ```go
  ToolRunner    shared.ToolLoopRunner
  KubectlRunner KubectlRunner
  Prom          PromQLQuerier
  MaxAgentRounds int
  ```
- `Analyzer` and `SystemPrompt` fields removed (the agent prompt lives in
  `agent.go`).
- `ProcessAlert` keeps the existing `userPrompt` assembly that prepends the
  alert header (`alertname`, `status`, `severity`, `namespace`, `StartsAt`)
  to `actx.FormatForPrompt()`. After `GatherContext` it calls
  `RunAgenticDiagnostics(ctx, deps.ToolRunner, deps.KubectlRunner, deps.Prom, userPrompt, deps.MaxAgentRounds)`
  instead of `deps.Analyzer.Analyze(...)`. The error / cooldown-clear /
  failure-notification flow is unchanged.
- The existing `pipeline_test.go` only checks for `StartsAt` substring,
  which would not detect a silent drop of `alertname`/`status`/`severity`/
  `namespace`. The test is **strengthened** to assert the full header
  prefix verbatim — `## Alert: <alertname>\n- Status: …\n- Severity: …\n- Namespace: …\n- StartsAt: …\n\n` — so any future refactor that mutates
  the header order or drops a field fails the test.

### Modified: `cmd/k8s-analyzer/main.go`

- `claudeClient` is wired in as `ToolRunner` (it already implements both
  `Analyzer` and `ToolLoopRunner`).
- Instantiate `kubectlSubprocess{}` and inject as `KubectlRunner`.
- Drop the `ALLOWED_NAMESPACES` env handling and the local `nsList` slice.
- Add `MAX_AGENT_ROUNDS` parsing (same bounds as checkmk: default 10,
  range 1–50).
- Remove the local `systemPrompt` constant (now lives in `agent.go`).

### Modified: `Dockerfile`

- The k8s-analyzer target's builder stage downloads the official `kubectl`
  binary (pinned version, sha256-verified) and copies it into the runtime
  stage at `/usr/local/bin/kubectl`.
- The checkmk-analyzer target is unchanged.

### Modified: `README.md`, `CLAUDE.md`

- Document that the k8s-analyzer is now agentic.
- New env: `MAX_AGENT_ROUNDS` (default 10).
- Removed env: `ALLOWED_NAMESPACES`.
- Note: the ServiceAccount needs a read-only ClusterRole (`get`, `list`,
  `watch` on the resources Claude should investigate). Sensitive resources
  (e.g. `Secret`) should be excluded from the role to keep them out of reach.

## Observability

### Metrics (added to `shared.PrometheusMetrics`)

- `agent_tool_calls_total{source, tool, outcome}` — counter; `source` is
  the existing `k8s` / `checkmk` label (CheckMK gets retro-fitted in this
  PR for symmetry). `tool` ∈ `kubectl_exec | promql_query | execute_command`.
  `outcome` ∈ `ok | rejected_validation | rejected_verb | exec_error |
  nonzero_exit | timeout`.
- `agent_tool_duration_seconds{source, tool}` — histogram; per-call
  wall-clock latency.
- `agent_rounds_used{source}` — histogram; observed once per
  `RunToolLoop` completion. `_count - exhausted_count` answers "how often
  did Claude end naturally vs. hit the cap".
- `agent_rounds_exhausted_total{source}` — counter; incremented when
  `RunToolLoop` returns via the forced-summary path.

### Logs

Per-tool `slog.Info` with `{tool, argv | query, duration_ms, outcome}`
fields (described in `agent.go` section). Plus a per-loop `slog.Info` at
end with `{rounds_used, exhausted, total_tool_calls, final_outcome}`.

## Error Handling

- Tool-call non-zero exit → output (stdout + stderr + exit status) goes back
  to Claude as the tool result so RBAC `Forbidden` and `not found` are
  visible and recoverable.
- argv / query validation errors → string returned to Claude (not a
  pipeline-level failure).
- `RunToolLoop` failure (API error, max-tokens, parse error) → unchanged
  pipeline behavior: `Cooldown.Clear`, `AlertsFailed.Add`, ntfy failure
  notification.
- Panic inside a tool handler → `recover` wrapper inside
  `RunAgenticDiagnostics`, returns a synthetic tool-result string so the
  loop survives.
- `kubectl` binary missing → first tool call fails with an exec error,
  string is returned to Claude, operator sees the failure in the analysis
  output. No startup probe, since the static prefetch uses client-go and
  does not need the binary.

## Testing Strategy

- TDD-first for all new code. Each `parseKubectlInput` / `parsePromQLInput`
  invariant gets a failing test before its implementation.
- Use `os.Args[0] -test.run=TestHelperProcess` for the subprocess-based
  `kubectlSubprocess` test (Go standard pattern, no temp file needed).
- Reuse the existing fake `kubernetes.Interface` for the pipeline integration
  test that verifies the static prefetch + agentic call both run.
- Coverage target: ≥80 % for `agent.go`, matching the checkmk baseline.

## Verification Before Merge

- `go test ./...` passes.
- `CGO_ENABLED=0 go build -o k8s-analyzer ./cmd/k8s-analyzer/` succeeds.
- `CGO_ENABLED=0 go build -o checkmk-analyzer ./cmd/checkmk-analyzer/` succeeds.
- Local Docker build of both targets — the k8s image contains
  `/usr/local/bin/kubectl`, the checkmk image does not.
