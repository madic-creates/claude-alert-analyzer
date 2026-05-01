package k8s

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
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
	}
	return nil
}
