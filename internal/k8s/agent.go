package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
)

// Argv-shape limits — identical to the values used in
// internal/checkmk/agent.go's parseCommandInput. Same threat model:
// a hallucinatory or adversarial Claude could emit oversized argv to OOM
// shellQuote, fill structured logs, or smuggle control characters that
// defeat exact-match denylist lookups.
const (
	maxArgvElements    = 64
	maxArgLen          = 4096
	maxTotalArgBytes   = 16384
	maxKubectlPromQLen = 4096 // also used by parsePromQLInput in Task 8
)

// parseKubectlInput validates the argv from a kubectl_exec tool call. It
// checks structural constraints (length, control characters) then delegates to
// validateKubectlFlags (global-flag denylist, Task 7) and validateKubectlVerb
// (verb allowlist, Task 6). The split keeps each concern in its own table test.
func parseKubectlInput(input json.RawMessage) ([]string, error) {
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
		if strings.TrimSpace(arg) != arg {
			return nil, fmt.Errorf("argument %d has leading or trailing whitespace", i)
		}
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
	if err := validateKubectlFlags(parsed.Command); err != nil {
		return nil, err
	}
	if err := validateKubectlVerb(parsed.Command); err != nil {
		return nil, err
	}
	return parsed.Command, nil
}

// allowedKubectlVerbs is the read-only built-in subcommand set. The agent
// system prompt promises read-only behavior; this allowlist enforces it
// for the subcommands the API server cannot see (config, kustomize,
// plugin) plus the obvious write verbs (delete, apply, …). RBAC is the
// final word for everything that does reach the API server.
var allowedKubectlVerbs = map[string]bool{
	"get": true, "describe": true, "logs": true, "top": true, "events": true,
	"explain": true, "version": true, "api-resources": true, "api-versions": true,
	"cluster-info": true, "auth": true, "rollout": true,
}

// allowedKubectlSubVerbs constrains verbs that have read-only sub-verbs.
// Any other sub-verb (or none) is rejected.
var allowedKubectlSubVerbs = map[string]map[string]bool{
	"auth":    {"can-i": true},
	"rollout": {"history": true},
}

// validateKubectlVerb runs after parseKubectlInput's byte-level checks. It
// finds the first non-flag token (the verb) and the second non-flag token
// (the sub-verb, when applicable) and rejects anything outside the allowlist.
func validateKubectlVerb(argv []string) error {
	verb, subVerb := extractVerbs(argv)
	if verb == "" {
		return fmt.Errorf("kubectl command has no verb; allowed verbs: %s", listAllowedVerbs())
	}
	if !allowedKubectlVerbs[verb] {
		return fmt.Errorf("command denied: kubectl %s is not permitted; allowed verbs: %s", verb, listAllowedVerbs())
	}
	if subs, hasSubs := allowedKubectlSubVerbs[verb]; hasSubs {
		if subVerb == "" || !subs[subVerb] {
			label := verb
			if subVerb != "" {
				label = verb + " " + subVerb
			}
			return fmt.Errorf("command denied: kubectl %s is not permitted; only %s %s is allowed",
				label, verb, allowedSubVerbList(verb))
		}
	}
	return nil
}

func extractVerbs(argv []string) (verb, subVerb string) {
	for _, a := range argv {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if verb == "" {
			verb = a
			continue
		}
		subVerb = a
		return
	}
	return
}

func listAllowedVerbs() string {
	keys := make([]string, 0, len(allowedKubectlVerbs))
	for k := range allowedKubectlVerbs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

func allowedSubVerbList(verb string) string {
	subs := allowedKubectlSubVerbs[verb]
	keys := make([]string, 0, len(subs))
	for k := range subs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

// deniedKubectlGlobalFlags lists flags that swap the cluster identity, target
// server, or auth credentials. They are rejected anywhere in argv before the
// verb is even examined: an allowed verb (get) used with an alternate
// kubeconfig defeats RBAC entirely.
var deniedKubectlGlobalFlags = map[string]bool{
	"--kubeconfig":               true,
	"--server":                   true,
	"-s":                         true, // short alias for --server
	"--token":                    true,
	"--token-file":               true,
	"--as":                       true,
	"--as-group":                 true,
	"--as-uid":                   true,
	"--user":                     true,
	"--cluster":                  true,
	"--context":                  true,
	"--certificate-authority":    true,
	"--client-certificate":       true,
	"--client-key":               true,
	"--insecure-skip-tls-verify": true,
	"--password":                 true,
	"--username":                 true,
	"--tls-server-name":          true,
}

// validateKubectlFlags rejects any argv element that names a denied global flag,
// in either the "--flag value" form (exact-token match) or the "--flag=value"
// form (prefix match up to the "="). The single-dash "-s" form is matched only
// as an exact token so that per-subcommand short flags like "--since" or "-c"
// are unaffected.
func validateKubectlFlags(argv []string) error {
	for _, a := range argv {
		// Exact-token match (covers "--kubeconfig" alone before its value, and "-s")
		if deniedKubectlGlobalFlags[a] {
			return fmt.Errorf("command denied: %s is not permitted; the in-cluster ServiceAccount is the only allowed identity (other denied flags include --kubeconfig, --server, --token, --as, --user, --cluster, --context, --client-*, --certificate-authority, --insecure-skip-tls-verify, --password, --username)", a)
		}
		// "--flag=value" form: split on the first "=" and check the head.
		if strings.HasPrefix(a, "--") {
			if eq := strings.IndexByte(a, '='); eq != -1 {
				if deniedKubectlGlobalFlags[a[:eq]] {
					return fmt.Errorf("command denied: %s is not permitted; the in-cluster ServiceAccount is the only allowed identity", a[:eq])
				}
			}
		}
		// Single-dash short flag with =, e.g. "-s=https://attacker.com"
		// kubectl accepts this form for short flags, so it must be denied
		// to close the -s bypass equivalent to --server=value.
		if len(a) > 1 && a[0] == '-' && a[1] != '-' {
			if eq := strings.IndexByte(a, '='); eq != -1 {
				if deniedKubectlGlobalFlags[a[:eq]] {
					return fmt.Errorf("command denied: %s is not permitted; the in-cluster ServiceAccount is the only allowed identity", a[:eq])
				}
			}
		}
	}
	return nil
}

// kubectlTool is the Claude tool definition for argv-based kubectl execution.
// The schema mirrors checkmk's execute_command tool — one argv array, no shell.
var kubectlTool = shared.Tool{
	Name:        "kubectl_exec",
	Description: "Run a read-only kubectl command. The command is passed as an argv array (no shell). Examples: [\"get\",\"pods\",\"-n\",\"monitoring\",\"-o\",\"wide\"], [\"describe\",\"pod\",\"prom-0\",\"-n\",\"monitoring\"], [\"logs\",\"pod-x\",\"-n\",\"db\",\"--tail=100\"], [\"top\",\"nodes\"]. Allowed verbs: get, describe, logs, top, events, explain, version, api-resources, api-versions, cluster-info, auth can-i, rollout history.",
	InputSchema: shared.InputSchema{
		Type: "object",
		Properties: map[string]shared.Property{
			"command": {
				Type:        "array",
				Description: "kubectl arguments as argv array, without the leading 'kubectl'",
				Items:       &shared.Items{Type: "string"},
			},
		},
		Required: []string{"command"},
	},
}

// promqlTool is the Claude tool definition for arbitrary PromQL queries
// against the configured Prometheus instance.
var promqlTool = shared.Tool{
	Name:        "promql_query",
	Description: "Run a PromQL query against Prometheus. Returns time-series results. Example: 'rate(http_requests_total[5m])'.",
	InputSchema: shared.InputSchema{
		Type: "object",
		Properties: map[string]shared.Property{
			"query": {
				Type:        "string",
				Description: "PromQL expression",
			},
		},
		Required: []string{"query"},
	},
}

// agentSystemPromptTemplate is the system prompt for the k8s agentic loop.
// %d is replaced with the actual maxRounds value at call time so Claude's
// self-reported round budget always matches the real limit, exactly as in
// checkmk's agentSystemPromptForRounds.
const agentSystemPromptTemplate = `You are a Kubernetes SRE analyst investigating a monitoring alert.

Your task:
1. Use kubectl_exec to run read-only kubectl commands and promql_query for Prometheus queries.
2. Investigate the alert across pods, deployments, events, logs, and metrics.
3. When you have enough information, stop calling tools and write your analysis.

Guidelines:
- Read-only commands only. Allowed kubectl verbs: get, describe, logs, top, events, explain, version, api-resources, api-versions, cluster-info, ` + "`auth can-i`, `rollout history`" + `.
- NEVER use: delete, apply, create, edit, patch, replace, scale, the rest of rollout (status, restart, pause, resume, undo), cordon/drain/uncordon, exec, cp, port-forward, proxy, debug, attach.
- NEVER pass: --kubeconfig, --server, --token, --as, --user, --cluster, --context, --certificate-authority, --client-*, --insecure-skip-tls-verify, or any other flag that overrides cluster identity or auth — they are rejected by the runtime.
- The ServiceAccount's RBAC permissions decide what is actually allowed; if a command fails with "Forbidden", do NOT retry — pick a different angle.
- You have a maximum of %d tool rounds.
- Static context (Prometheus metrics, recent events, pod status, pod logs) is already in the user message — start by reading it before issuing your first tool call.
- Begin broad (cluster-wide events, namespace overview) then narrow down based on findings.

Output your final analysis in markdown (headings, bold, lists, code blocks — no tables):
1. Root cause
2. Severity and blast radius
3. Remediation steps (concrete kubectl commands the operator should run)
4. Correlations between alerts/services if applicable

Reference actual values from command outputs and metric results. Keep response under 500 words.
Start directly with the analysis — no preamble, meta-commentary, or introductory sentences.`

func agentSystemPromptForRounds(maxRounds int) string {
	return fmt.Sprintf(agentSystemPromptTemplate, maxRounds)
}

// KubectlRunner is the seam between the agent loop and the actual kubectl
// subprocess. The default implementation (kubectlSubprocess) shells out;
// tests substitute their own implementation.
type KubectlRunner interface {
	Exec(ctx context.Context, argv []string, timeout time.Duration) (string, error)
}

// kubectlSubprocess invokes a fixed kubectl binary path with a scrubbed
// environment. The constructor performs a single os.Stat at startup and
// logs a warning if the binary is missing — but does not fail startup,
// because the static prefetch (which uses client-go) keeps working.
type kubectlSubprocess struct {
	Path string
	Env  []string
}

const defaultKubectlPath = "/usr/local/bin/kubectl"

// NewKubectlSubprocess constructs a runner that invokes the kubectl binary
// at path (default: /usr/local/bin/kubectl). The env slice contains only
// HOME and USER taken from the runtime environment; everything else
// (KUBECONFIG, PATH, proxy vars, LD_PRELOAD) is dropped so that no
// inherited variable can redirect kubectl's auth or behavior.
func NewKubectlSubprocess(path string) *kubectlSubprocess {
	if path == "" {
		path = defaultKubectlPath
	}
	if _, err := os.Stat(path); err != nil {
		slog.Warn("kubectl binary not found at startup", "path", path, "error", err)
	}
	env := []string{
		"HOME=" + os.Getenv("HOME"),
		"USER=" + os.Getenv("USER"),
	}
	return &kubectlSubprocess{Path: path, Env: env}
}

func (k *kubectlSubprocess) Exec(ctx context.Context, argv []string, timeout time.Duration) (string, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, k.Path, argv...)
	cmd.Env = k.Env
	if home := os.Getenv("HOME"); home != "" {
		cmd.Dir = home
	}

	out, err := cmd.CombinedOutput()
	return string(out), err
}

// parsePromQLInput validates a promql_query tool call. The 4096-byte cap is
// the same as the per-argument cap used by kubectl_exec; control characters
// are rejected for the same prompt-injection reasons (a query embedded with
// "\n## INJECTED" inside an error path could pollute the model context).
func parsePromQLInput(input json.RawMessage) (string, error) {
	var parsed struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal(input, &parsed); err != nil {
		return "", fmt.Errorf("parse query input: %w", err)
	}
	if strings.TrimSpace(parsed.Query) == "" {
		return "", fmt.Errorf("empty query")
	}
	if len(parsed.Query) > maxKubectlPromQLen {
		return "", fmt.Errorf("query exceeds maximum length of %d bytes", maxKubectlPromQLen)
	}
	for _, r := range parsed.Query {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return "", fmt.Errorf("query contains control character 0x%02x", r)
		}
	}
	return parsed.Query, nil
}
