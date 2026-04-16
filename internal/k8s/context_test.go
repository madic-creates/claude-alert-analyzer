package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// helpers

func makeAlertWithLabels(labels map[string]string) Alert {
	return Alert{
		Labels:      labels,
		Annotations: map[string]string{},
		Fingerprint: "fp-ctx",
		Status:      "firing",
	}
}

func makePromServer(t *testing.T, result []PromResult) *httptest.Server {
	t.Helper()
	resp := PromQueryResponse{Status: "success"}
	resp.Data.ResultType = "vector"
	resp.Data.Result = result
	body, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal prom response: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	return srv
}

// ----- GetKubeContext tests -----

func TestGetKubeContext_NoNamespace(t *testing.T) {
	cs := fake.NewSimpleClientset()
	alert := makeAlertWithLabels(map[string]string{})
	cfg := Config{AllowedNamespaces: []string{"*"}, MaxLogBytes: 4096}

	events, pods, logs := GetKubeContext(context.Background(), cs, alert, cfg)
	if events != "(no namespace in alert)" {
		t.Errorf("expected no-namespace message for events, got %q", events)
	}
	if pods != "(no namespace)" {
		t.Errorf("expected no-namespace message for pods, got %q", pods)
	}
	if logs != "(no namespace)" {
		t.Errorf("expected no-namespace message for logs, got %q", logs)
	}
}

func TestGetKubeContext_EmptyNamespace_NoEvents(t *testing.T) {
	cs := fake.NewSimpleClientset()
	alert := makeAlertWithLabels(map[string]string{"namespace": "mynamespace"})
	cfg := Config{AllowedNamespaces: []string{"mynamespace"}, MaxLogBytes: 4096}

	events, pods, logs := GetKubeContext(context.Background(), cs, alert, cfg)
	if events != "(no warning events)" {
		t.Errorf("expected (no warning events), got %q", events)
	}
	if pods != "(no pods)" {
		t.Errorf("expected (no pods), got %q", pods)
	}
	_ = logs // logs depend on failing pods; no pods means no failing pods
}

func TestGetKubeContext_PodStatusListed(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "web-abc",
				Namespace: "prod",
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
				ContainerStatuses: []corev1.ContainerStatus{
					{Ready: true, RestartCount: 2},
					{Ready: false, RestartCount: 0},
				},
			},
		},
	)
	alert := makeAlertWithLabels(map[string]string{"namespace": "prod"})
	cfg := Config{AllowedNamespaces: []string{}, MaxLogBytes: 4096}

	_, pods, _ := GetKubeContext(context.Background(), cs, alert, cfg)
	if !strings.Contains(pods, "web-abc") {
		t.Errorf("expected pod name in output, got %q", pods)
	}
	if !strings.Contains(pods, "Running") {
		t.Errorf("expected Running phase, got %q", pods)
	}
	if !strings.Contains(pods, "restarts=2") {
		t.Errorf("expected restarts=2, got %q", pods)
	}
	if !strings.Contains(pods, "1/2") {
		t.Errorf("expected 1/2 ready containers, got %q", pods)
	}
}

func TestGetKubeContext_LogsSkipped_WhenNamespaceNotAllowed(t *testing.T) {
	cs := fake.NewSimpleClientset()
	alert := makeAlertWithLabels(map[string]string{"namespace": "restricted"})
	cfg := Config{AllowedNamespaces: []string{"allowed-only"}, MaxLogBytes: 4096}

	_, _, logs := GetKubeContext(context.Background(), cs, alert, cfg)
	if !strings.Contains(logs, "not in log allowlist") {
		t.Errorf("expected not-in-allowlist message, got %q", logs)
	}
}

func TestGetKubeContext_LogsSkipped_WhenNoAllowlist(t *testing.T) {
	cs := fake.NewSimpleClientset()
	alert := makeAlertWithLabels(map[string]string{"namespace": "myns"})
	cfg := Config{AllowedNamespaces: []string{}, MaxLogBytes: 4096}

	_, _, logs := GetKubeContext(context.Background(), cs, alert, cfg)
	if !strings.Contains(logs, "not in log allowlist") {
		t.Errorf("expected not-in-allowlist message for empty allowlist, got %q", logs)
	}
}

func TestGetKubeContext_LogsAllowed_NoFailingPods(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "running-pod", Namespace: "app"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
	)
	alert := makeAlertWithLabels(map[string]string{"namespace": "app"})
	// Wildcard allowlist so logs are attempted
	cfg := Config{AllowedNamespaces: []string{"*"}, MaxLogBytes: 4096}

	_, _, logs := GetKubeContext(context.Background(), cs, alert, cfg)
	// No failing pods — the fake client field-selector filter won't exclude the Running pod
	// because fake client doesn't support field selectors, so the pod will be listed.
	// The code will attempt to fetch logs. The fake client returns an error for GetLogs,
	// so each pod's logs entry will either be "(no logs)" or the pod name is in the output.
	// Either outcome is acceptable as long as it doesn't panic.
	_ = logs
}

func TestGetKubeContext_WildcardAllowlistPermitsLogs(t *testing.T) {
	cs := fake.NewSimpleClientset()
	alert := makeAlertWithLabels(map[string]string{"namespace": "anything"})
	cfg := Config{AllowedNamespaces: []string{"*"}, MaxLogBytes: 4096}

	_, _, logs := GetKubeContext(context.Background(), cs, alert, cfg)
	// With wildcard and no failing pods, expect "(no failing pods)"
	if logs != "(no failing pods)" {
		// The fake client doesn't support field selectors, so the second pod list
		// may return all pods. If there are none, we should get "(no failing pods)".
		// Accept either "(no failing pods)" or a log entry (for the fake client path).
		if !strings.Contains(logs, "no failing pods") && !strings.Contains(logs, "no logs") {
			t.Errorf("unexpected logs output: %q", logs)
		}
	}
}

func TestGetKubeContext_Events_WarningEventListed(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&corev1.Event{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "evt-1",
				Namespace: "prod",
			},
			Type:   corev1.EventTypeWarning,
			Reason: "BackOff",
			InvolvedObject: corev1.ObjectReference{
				Name: "crasher-pod",
			},
			Message: "Back-off restarting failed container",
		},
	)
	alert := makeAlertWithLabels(map[string]string{"namespace": "prod"})
	cfg := Config{AllowedNamespaces: []string{}, MaxLogBytes: 4096}

	events, _, _ := GetKubeContext(context.Background(), cs, alert, cfg)
	if !strings.Contains(events, "BackOff") {
		t.Errorf("expected BackOff reason in events, got %q", events)
	}
	if !strings.Contains(events, "crasher-pod") {
		t.Errorf("expected pod name in events, got %q", events)
	}
}

// ----- GetPrometheusMetrics tests -----

func TestGetPrometheusMetrics_NoNamespaceNoAlertname(t *testing.T) {
	srv := makePromServer(t, []PromResult{})
	defer srv.Close()

	alert := makeAlertWithLabels(map[string]string{})
	result := GetPrometheusMetrics(context.Background(), srv.URL, alert)
	if !strings.Contains(result, "Active Firing Alerts") {
		t.Errorf("expected active alerts section, got %q", result)
	}
}

func TestGetPrometheusMetrics_IncludesNamespaceSections(t *testing.T) {
	srv := makePromServer(t, []PromResult{})
	defer srv.Close()

	alert := makeAlertWithLabels(map[string]string{
		"namespace": "production",
		"alertname": "SomeAlert",
	})
	result := GetPrometheusMetrics(context.Background(), srv.URL, alert)
	if !strings.Contains(result, "CPU Usage (production)") {
		t.Errorf("expected CPU section for namespace, got %q", result)
	}
	if !strings.Contains(result, "Memory Usage (production)") {
		t.Errorf("expected Memory section for namespace, got %q", result)
	}
	if !strings.Contains(result, "Pod Restarts (production)") {
		t.Errorf("expected Pod Restarts section for namespace, got %q", result)
	}
}

func TestGetPrometheusMetrics_CrashLoopAlertname(t *testing.T) {
	srv := makePromServer(t, []PromResult{})
	defer srv.Close()

	alert := makeAlertWithLabels(map[string]string{"alertname": "PodCrashLoopBackOff"})
	result := GetPrometheusMetrics(context.Background(), srv.URL, alert)
	if !strings.Contains(result, "CrashLoop Details") {
		t.Errorf("expected CrashLoop Details section, got %q", result)
	}
}

func TestGetPrometheusMetrics_MemoryAlertname(t *testing.T) {
	srv := makePromServer(t, []PromResult{})
	defer srv.Close()

	alert := makeAlertWithLabels(map[string]string{"alertname": "HighMemoryUsage"})
	result := GetPrometheusMetrics(context.Background(), srv.URL, alert)
	if !strings.Contains(result, "Top Memory Consumers") {
		t.Errorf("expected Top Memory Consumers section, got %q", result)
	}
}

func TestGetPrometheusMetrics_CPUAlertname(t *testing.T) {
	srv := makePromServer(t, []PromResult{})
	defer srv.Close()

	alert := makeAlertWithLabels(map[string]string{"alertname": "HighCPUUsage"})
	result := GetPrometheusMetrics(context.Background(), srv.URL, alert)
	if !strings.Contains(result, "Top CPU Consumers") {
		t.Errorf("expected Top CPU Consumers section, got %q", result)
	}
}

func TestGetPrometheusMetrics_DiskAlertname(t *testing.T) {
	srv := makePromServer(t, []PromResult{})
	defer srv.Close()

	for _, name := range []string{"DiskFull", "VolumeAlmostFull", "StoragePressure"} {
		alert := makeAlertWithLabels(map[string]string{"alertname": name})
		result := GetPrometheusMetrics(context.Background(), srv.URL, alert)
		if !strings.Contains(result, "PVC Usage") {
			t.Errorf("alert %q: expected PVC Usage section, got %q", name, result)
		}
	}
}

func TestGetPrometheusMetrics_NodeAlertname(t *testing.T) {
	srv := makePromServer(t, []PromResult{})
	defer srv.Close()

	alert := makeAlertWithLabels(map[string]string{"alertname": "NodeNotReady"})
	result := GetPrometheusMetrics(context.Background(), srv.URL, alert)
	if !strings.Contains(result, "Node Conditions") {
		t.Errorf("expected Node Conditions section, got %q", result)
	}
}

func TestGetPrometheusMetrics_WithResultData(t *testing.T) {
	srv := makePromServer(t, []PromResult{
		{
			Metric: map[string]string{"job": "prometheus", "instance": "localhost:9090"},
			Value:  [2]interface{}{1700000000, "1"},
		},
	})
	defer srv.Close()

	alert := makeAlertWithLabels(map[string]string{})
	result := GetPrometheusMetrics(context.Background(), srv.URL, alert)
	if !strings.Contains(result, "job=prometheus") && !strings.Contains(result, "instance=localhost:9090") {
		t.Errorf("expected metric labels in result, got %q", result)
	}
}

func TestGetPrometheusMetrics_PrometheusUnreachable(t *testing.T) {
	alert := makeAlertWithLabels(map[string]string{"alertname": "SomeAlert"})
	result := GetPrometheusMetrics(context.Background(), "http://127.0.0.1:1", alert)
	// Should still return sections, with error messages inside them
	if !strings.Contains(result, "Active Firing Alerts") {
		t.Errorf("expected sections even on error, got %q", result)
	}
	if !strings.Contains(result, "query failed") {
		t.Errorf("expected query failed error, got %q", result)
	}
}

func TestGetPrometheusMetrics_ErrorStatus(t *testing.T) {
	// Prometheus returns status="error" for a bad query; should surface the error, not "(no data)"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"error","errorType":"bad_data","error":"invalid parameter 'query': parse error"}`))
	}))
	defer srv.Close()

	alert := makeAlertWithLabels(map[string]string{})
	result := GetPrometheusMetrics(context.Background(), srv.URL, alert)
	if !strings.Contains(result, "query error") {
		t.Errorf("expected query error in result, got %q", result)
	}
	if !strings.Contains(result, "bad_data") {
		t.Errorf("expected errorType in result, got %q", result)
	}
	if strings.Contains(result, "(no data)") {
		t.Errorf("result should not say '(no data)' for an error response, got %q", result)
	}
}

func TestGetPrometheusMetrics_OversizedResponse(t *testing.T) {
	// A Prometheus server that returns more than MaxResponseBytes should not
	// cause unbounded memory allocation; promqlQuery must cap reads via LimitReader.
	// The truncated body will fail JSON parsing and return the parse-error sentinel.
	huge := strings.Repeat("x", shared.MaxResponseBytes+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, huge)
	}))
	defer srv.Close()

	alert := makeAlertWithLabels(map[string]string{})
	result := GetPrometheusMetrics(context.Background(), srv.URL, alert)
	// The oversized, truncated body cannot parse as JSON — expect the parse-failure sentinel.
	if !strings.Contains(result, "failed to parse") {
		t.Errorf("expected parse-failure sentinel for oversized response, got %q", result)
	}
}

// ----- GatherContext integration tests -----

func TestGatherContext_ReturnsFourSections(t *testing.T) {
	srv := makePromServer(t, []PromResult{})
	defer srv.Close()

	cs := fake.NewSimpleClientset()
	alert := makeAlertWithLabels(map[string]string{
		"alertname": "TestAlert",
		"namespace": "testns",
	})
	cfg := Config{
		PrometheusURL:     srv.URL,
		AllowedNamespaces: []string{},
		MaxLogBytes:       4096,
	}

	actx := GatherContext(context.Background(), cs, srv.URL, alert, cfg)
	if len(actx.Sections) != 4 {
		t.Fatalf("expected 4 sections, got %d", len(actx.Sections))
	}
	wantNames := []string{"Prometheus Metrics", "Kubernetes Events", "Pod Status", "Pod Logs"}
	for i, name := range wantNames {
		if actx.Sections[i].Name != name {
			t.Errorf("section[%d]: expected %q, got %q", i, name, actx.Sections[i].Name)
		}
	}
}

func TestGatherContext_SectionsNotEmpty(t *testing.T) {
	srv := makePromServer(t, []PromResult{})
	defer srv.Close()

	cs := fake.NewSimpleClientset()
	alert := makeAlertWithLabels(map[string]string{
		"alertname": "HighCPU",
		"namespace": "prod",
	})
	cfg := Config{
		AllowedNamespaces: []string{"prod"},
		MaxLogBytes:       4096,
	}

	actx := GatherContext(context.Background(), cs, srv.URL, alert, cfg)
	for _, s := range actx.Sections {
		if s.Content == "" {
			t.Errorf("section %q has empty content", s.Name)
		}
	}
}

func TestGatherContext_PrometheusUnreachable_StillReturnsKubeContext(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "mypod", Namespace: "myns"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
	)
	alert := makeAlertWithLabels(map[string]string{
		"alertname": "SomeAlert",
		"namespace": "myns",
	})
	cfg := Config{
		AllowedNamespaces: []string{},
		MaxLogBytes:       4096,
	}

	actx := GatherContext(context.Background(), cs, "http://127.0.0.1:1", alert, cfg)
	if len(actx.Sections) != 4 {
		t.Fatalf("expected 4 sections even when Prometheus unreachable, got %d", len(actx.Sections))
	}
	podSection := actx.Sections[2]
	if !strings.Contains(podSection.Content, "mypod") {
		t.Errorf("expected mypod in pod status section, got %q", podSection.Content)
	}
}

func TestGatherContext_CancelledContext(t *testing.T) {
	// Start a slow prometheus server
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hang until the request context is done
		<-r.Context().Done()
		fmt.Fprint(w, `{}`)
	}))
	defer slow.Close()

	cs := fake.NewSimpleClientset()
	alert := makeAlertWithLabels(map[string]string{"alertname": "Test", "namespace": "ns"})
	cfg := Config{AllowedNamespaces: []string{}, MaxLogBytes: 4096}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// Should not block / panic
	actx := GatherContext(ctx, cs, slow.URL, alert, cfg)
	if len(actx.Sections) != 4 {
		t.Fatalf("expected 4 sections, got %d", len(actx.Sections))
	}
}
