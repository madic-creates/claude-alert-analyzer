package shared

import (
	"strings"
	"testing"
)

func TestClassifyToolError(t *testing.T) {
	tests := []struct {
		name string
		text string
		want ToolErrorClass
	}{
		{"kubectl rbac forbidden", `Error from server (Forbidden): pods is forbidden: User "system:serviceaccount:monitoring:analyzer" cannot list resource "pods"`, ToolErrorForbidden},
		{"context deadline exceeded", "round failed: context deadline exceeded", ToolErrorTimeout},
		{"signal killed", "signal: killed", ToolErrorTimeout},
		{"ssh timeout marker", "timeout after 10s", ToolErrorTimeout},
		{"client timeout", "Get \"http://prom:9090/api/v1/query\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)", ToolErrorTimeout},
		{"kubectl notfound", `Error from server (NotFound): pods "web-0" not found`, ToolErrorNotFound},
		{"missing resource type", `error: the server doesn't have a resource type "foo"`, ToolErrorNotFound},
		{"missing file", "cat: /var/log/foo.log: No such file or directory", ToolErrorNotFound},
		{"connection refused", `Get "http://prom:9090": dial tcp 10.0.0.1:9090: connect: connection refused`, ToolErrorUnreachable},
		{"no route to host", "dial tcp 10.0.0.9:443: no route to host", ToolErrorUnreachable},
		{"network unreachable", "connect: network is unreachable", ToolErrorUnreachable},
		{"dns failure", "dial tcp: lookup prom.monitoring: no such host", ToolErrorUnreachable},
		{"connection reset", "read tcp 10.0.0.1:443: connection reset by peer", ToolErrorUnreachable},
		{"permission denied", "cat: /etc/shadow: Permission denied", ToolErrorPermissionDenied},
		{"operation not permitted", "dmesg: read kernel buffer failed: Operation not permitted", ToolErrorPermissionDenied},
		{"command not found", "zsh:1: command not found: iotop", ToolErrorCommandNotFound},
		{"executable not found", `exec: "kubectl": executable file not found in $PATH`, ToolErrorCommandNotFound},
		{"unclassified exit status", "exit status 1", ToolErrorNone},
		{"empty", "", ToolErrorNone},
		{"case insensitive forbidden", "ERROR FROM SERVER (FORBIDDEN)", ToolErrorForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyToolError(tt.text); got != tt.want {
				t.Errorf("ClassifyToolError(%q) = %v, want %v", tt.text, got, tt.want)
			}
		})
	}
}

// TestToolErrorClass_Advisory pins the advisory contract: every real class
// yields a one-line "[hint: ...]" advisory, ToolErrorNone yields "".
func TestToolErrorClass_Advisory(t *testing.T) {
	classes := []ToolErrorClass{
		ToolErrorTimeout, ToolErrorForbidden, ToolErrorNotFound,
		ToolErrorUnreachable, ToolErrorPermissionDenied, ToolErrorCommandNotFound,
	}
	for _, c := range classes {
		adv := c.Advisory()
		if !strings.HasPrefix(adv, "[hint: ") {
			t.Errorf("class %v advisory %q does not start with %q", c, adv, "[hint: ")
		}
		if strings.ContainsRune(adv, '\n') {
			t.Errorf("class %v advisory must be a single line, got %q", c, adv)
		}
	}
	if got := ToolErrorNone.Advisory(); got != "" {
		t.Errorf("ToolErrorNone.Advisory() = %q, want empty", got)
	}
}
