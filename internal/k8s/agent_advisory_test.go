package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
)

// TestHandleKubectlTool_ForbiddenAdvisory verifies that an RBAC-forbidden
// kubectl failure is prefixed with a classification hint so the model stops
// retrying commands that will fail identically (issue #35).
func TestHandleKubectlTool_ForbiddenAdvisory(t *testing.T) {
	kc := &fakeKubectlRunner{
		response: `Error from server (Forbidden): secrets is forbidden: User "system:serviceaccount:monitoring:analyzer" cannot list resource "secrets"`,
		err:      fmt.Errorf("exit status 1"),
	}
	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetricsForTest(shared.ProductK8s)}

	out, err := handleKubectlTool(context.Background(), kc, metrics, "test-alert",
		json.RawMessage(`{"command":["get","secrets"]}`), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(out, "[hint: ") {
		t.Fatalf("expected advisory hint prefix, got: %q", out)
	}
	firstLine := out[:strings.IndexByte(out, '\n')]
	if !strings.Contains(strings.ToLower(firstLine), "forbidden") {
		t.Errorf("expected forbidden advisory in first line, got: %q", firstLine)
	}
	// The original tool result must still follow the advisory.
	if !strings.Contains(out, "$ kubectl get secrets") {
		t.Errorf("original command header missing from result: %q", out)
	}
}

// TestHandleKubectlTool_TimeoutAdvisory verifies the timeout class is
// detected from the runner error string.
func TestHandleKubectlTool_TimeoutAdvisory(t *testing.T) {
	kc := &fakeKubectlRunner{err: context.DeadlineExceeded}
	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetricsForTest(shared.ProductK8s)}

	out, err := handleKubectlTool(context.Background(), kc, metrics, "test-alert",
		json.RawMessage(`{"command":["logs","big-pod","-n","apps"]}`), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(out, "[hint: ") {
		t.Fatalf("expected advisory hint prefix, got: %q", out)
	}
	if !strings.Contains(strings.ToLower(out[:strings.IndexByte(out, '\n')]), "timed out") {
		t.Errorf("expected timeout advisory in first line, got: %q", out)
	}
}

// TestHandleKubectlTool_NoAdvisoryOnUnclassifiedError verifies that an error
// with no recognizable class is returned unchanged — no speculative hint.
func TestHandleKubectlTool_NoAdvisoryOnUnclassifiedError(t *testing.T) {
	kc := &fakeKubectlRunner{response: "some unrelated stderr", err: fmt.Errorf("exit status 1")}
	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetricsForTest(shared.ProductK8s)}

	out, err := handleKubectlTool(context.Background(), kc, metrics, "test-alert",
		json.RawMessage(`{"command":["get","pods"]}`), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(out, "[hint: ") {
		t.Errorf("unclassified error must not carry an advisory, got: %q", out)
	}
}

// TestHandleKubectlTool_NoAdvisoryOnSuccess verifies successful commands are
// never prefixed with a hint even when output mentions error-like words.
func TestHandleKubectlTool_NoAdvisoryOnSuccess(t *testing.T) {
	kc := &fakeKubectlRunner{response: "pod-x  CrashLoopBackOff  connection refused in logs"}
	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetricsForTest(shared.ProductK8s)}

	out, err := handleKubectlTool(context.Background(), kc, metrics, "test-alert",
		json.RawMessage(`{"command":["get","pods"]}`), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(out, "[hint: ") {
		t.Errorf("successful command must not carry an advisory, got: %q", out)
	}
}

// TestHandlePromQLTool_UnreachableAdvisory verifies that a Prometheus
// connection failure is prefixed with the unreachable advisory so the model
// stops issuing further PromQL calls that will fail the same way.
func TestHandlePromQLTool_UnreachableAdvisory(t *testing.T) {
	pq := &fakePromQLQuerier{err: fmt.Errorf(`Get "http://prom:9090/api/v1/query": dial tcp 10.0.0.1:9090: connect: connection refused`)}
	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetricsForTest(shared.ProductK8s)}

	out, err := handlePromQLTool(context.Background(), pq, metrics, "test-alert",
		json.RawMessage(`{"query":"up"}`), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(out, "[hint: ") {
		t.Fatalf("expected advisory hint prefix, got: %q", out)
	}
	if !strings.Contains(strings.ToLower(out[:strings.IndexByte(out, '\n')]), "unreachable") {
		t.Errorf("expected unreachable advisory in first line, got: %q", out)
	}
	if !strings.Contains(out, "# PromQL: up") {
		t.Errorf("original query header missing from result: %q", out)
	}
}
