package shared

import "strings"

// ToolErrorClass categorizes agent tool failures so handlers can prepend a
// one-line advisory to the tool result. Without it the model receives a raw
// error string and often retries near-identical commands that fail the same
// way, burning round budget (issue #35). Callers decide which classes apply
// to a given failure path: transport errors should only be matched against
// transport-shaped classes (timeout, unreachable), remote-command stderr only
// against stderr-shaped classes (permission denied, not found), so that
// error-like words inside command output cannot produce a misleading hint.
type ToolErrorClass int

const (
	ToolErrorNone ToolErrorClass = iota
	ToolErrorTimeout
	ToolErrorForbidden
	ToolErrorNotFound
	ToolErrorUnreachable
	ToolErrorPermissionDenied
	ToolErrorCommandNotFound
)

// toolErrorPatterns maps each class to lowercase substrings that identify it.
// Order matters: earlier entries win, so ToolErrorCommandNotFound (whose
// patterns contain "not found") must precede the generic ToolErrorNotFound.
var toolErrorPatterns = []struct {
	class    ToolErrorClass
	patterns []string
}{
	{ToolErrorTimeout, []string{
		"context deadline exceeded", "timed out", "timeout after",
		"signal: killed", "i/o timeout",
	}},
	{ToolErrorForbidden, []string{"forbidden"}},
	{ToolErrorPermissionDenied, []string{"permission denied", "operation not permitted"}},
	{ToolErrorCommandNotFound, []string{"command not found", "executable file not found"}},
	{ToolErrorNotFound, []string{
		"not found", "no such file or directory", "doesn't have a resource type",
	}},
	{ToolErrorUnreachable, []string{
		"connection refused", "no route to host", "network is unreachable",
		"connection reset", "no such host",
	}},
}

// ClassifyToolError matches text (an error string, optionally combined with
// captured stderr) against known failure signatures and returns the first
// matching class, or ToolErrorNone.
func ClassifyToolError(text string) ToolErrorClass {
	lower := strings.ToLower(text)
	for _, entry := range toolErrorPatterns {
		for _, p := range entry.patterns {
			if strings.Contains(lower, p) {
				return entry.class
			}
		}
	}
	return ToolErrorNone
}

// toolErrorAdvisories holds the one-line hint prepended to a classified tool
// result. Each tells the model what the failure means and how to avoid
// wasting the next round on an identical retry.
var toolErrorAdvisories = map[ToolErrorClass]string{
	ToolErrorTimeout:          "[hint: the command timed out — narrow its scope (fewer items, --tail, a shorter time range) or try a lighter command; do not repeat it unchanged]",
	ToolErrorForbidden:        "[hint: access forbidden (RBAC) — this identity cannot read that resource; do not retry the same command, investigate via a different resource or data source]",
	ToolErrorNotFound:         "[hint: resource not found — verify the exact name and namespace (list the parent resource first) instead of retrying unchanged]",
	ToolErrorUnreachable:      "[hint: target unreachable — the endpoint did not accept the connection; further similar calls will likely fail the same way]",
	ToolErrorPermissionDenied: "[hint: permission denied — no elevated privileges are available (no root/sudo); choose a file or command readable by the current user]",
	ToolErrorCommandNotFound:  "[hint: command not found on the target — use an alternative tool that provides the same information]",
}

// Advisory returns the one-line hint for the class, or "" for ToolErrorNone.
func (c ToolErrorClass) Advisory() string {
	return toolErrorAdvisories[c]
}
