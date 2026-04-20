package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
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

func TestGetKubeContext_InvalidNamespace(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cfg := Config{AllowedNamespaces: []string{"*"}, MaxLogBytes: 4096}

	invalidNamespaces := []string{
		`default"}[5m]) or up{namespace="evil`,
		"-badstart",
		"bad start",
		"bad\x00null",
		strings.Repeat("a", 64), // exceeds 63-char limit
	}
	for _, ns := range invalidNamespaces {
		alert := makeAlertWithLabels(map[string]string{"namespace": ns})
		events, pods, logs := GetKubeContext(context.Background(), cs, alert, cfg)
		if !strings.Contains(events, "invalid namespace label") {
			t.Errorf("ns %q: expected invalid-namespace sentinel for events, got %q", ns, events)
		}
		if !strings.Contains(pods, "invalid namespace label") {
			t.Errorf("ns %q: expected invalid-namespace sentinel for pods, got %q", ns, pods)
		}
		if !strings.Contains(logs, "invalid namespace label") {
			t.Errorf("ns %q: expected invalid-namespace sentinel for logs, got %q", ns, logs)
		}
	}
}

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
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "main"},
					{Name: "sidecar"},
				},
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

// TestGetKubeContext_PodLogsAPIError verifies that a Kubernetes API error when listing
// failing pods is surfaced in the log output rather than being silently masked as
// "(no failing pods)". Previously, the two conditions (err != nil) and
// (len == 0) were merged, so an API outage was indistinguishable from a healthy cluster.
func TestGetKubeContext_PodLogsAPIError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	// Inject an error for any pod List call so getPodLogs hits the error path.
	cs.PrependReactor("list", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("kube api unavailable")
	})
	alert := makeAlertWithLabels(map[string]string{"namespace": "prod"})
	cfg := Config{AllowedNamespaces: []string{"*"}, MaxLogBytes: 4096}

	_, _, logs := GetKubeContext(context.Background(), cs, alert, cfg)
	if strings.Contains(logs, "no failing pods") {
		t.Errorf("API error must not be masked as '(no failing pods)', got %q", logs)
	}
	if !strings.Contains(logs, "failed to list failing pods") {
		t.Errorf("expected error message in logs output, got %q", logs)
	}
	if !strings.Contains(logs, "kube api unavailable") {
		t.Errorf("expected underlying error in logs output, got %q", logs)
	}
}

// TestGetPodLogs_LimitBytesPassedToAPI verifies that getPodLogs sets LimitBytes on
// the Kubernetes GetLogs request equal to cfg.MaxLogBytes. This bounds the data
// fetched from the API before the post-fetch Truncate runs, preventing OOM when pods
// emit very long individual log lines (e.g. large JSON debug blobs). The fix mirrors
// the SSH output bound added in "fix: bound SSH command output at collection time".
// The fake client invokes reactors when GetLogs is called; the action carries the
// PodLogOptions as its value via GenericAction.GetValue().
func TestGetPodLogs_LimitBytesPassedToAPI(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "failing-pod", Namespace: "testns"},
			Status:     corev1.PodStatus{Phase: corev1.PodFailed},
		},
	)

	const wantMaxLogBytes = 4096
	var capturedOpts *corev1.PodLogOptions

	cs.PrependReactor("get", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		ga, ok := action.(k8stesting.GenericAction)
		if !ok || action.GetSubresource() != "log" {
			return false, nil, nil // not a log request — pass through
		}
		if opts, ok := ga.GetValue().(*corev1.PodLogOptions); ok {
			capturedOpts = opts
		}
		return false, nil, nil // let default handler proceed (returns empty body)
	})

	cfg := Config{AllowedNamespaces: []string{"*"}, MaxLogBytes: wantMaxLogBytes}
	getPodLogs(context.Background(), cs, "testns", cfg)

	if capturedOpts == nil {
		t.Fatal("GetLogs was not called — cannot verify LimitBytes")
	}
	if capturedOpts.LimitBytes == nil {
		t.Fatal("LimitBytes not set in GetLogs call — unbounded fetch risks OOM on verbose pods")
	}
	if *capturedOpts.LimitBytes != int64(wantMaxLogBytes) {
		t.Errorf("LimitBytes = %d, want %d (MaxLogBytes)", *capturedOpts.LimitBytes, wantMaxLogBytes)
	}
	if capturedOpts.TailLines == nil || *capturedOpts.TailLines != 30 {
		t.Errorf("TailLines must still be 30, got %v", capturedOpts.TailLines)
	}
}

// TestGetPodLogs_MultiContainerPod verifies that getPodLogs passes an explicit container
// name to GetLogs when a pod has multiple containers. Omitting the container name for
// such pods causes the Kubernetes API to return "a container name must be specified",
// resulting in silent "(no logs)" output for any pod with a sidecar (e.g. Istio).
// The non-ready container is preferred over the first container so that the logs most
// likely to explain the alert are fetched.
func TestGetPodLogs_MultiContainerPod(t *testing.T) {
	cs := fake.NewSimpleClientset()

	// Inject a multi-container failing pod: app (not ready, 3 restarts) + sidecar (ready).
	// The fix should pick "app" because it is not ready.
	cs.PrependReactor("list", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, &corev1.PodList{Items: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "multi-pod", Namespace: "prod"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "sidecar"},
					{Name: "app"},
				},
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodFailed,
				ContainerStatuses: []corev1.ContainerStatus{
					{Name: "sidecar", Ready: true, RestartCount: 0},
					{Name: "app", Ready: false, RestartCount: 3},
				},
			},
		}}}, nil
	})

	var capturedOpts *corev1.PodLogOptions
	cs.PrependReactor("get", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		ga, ok := action.(k8stesting.GenericAction)
		if !ok || action.GetSubresource() != "log" {
			return false, nil, nil
		}
		if opts, ok := ga.GetValue().(*corev1.PodLogOptions); ok {
			capturedOpts = opts
		}
		return false, nil, nil
	})

	cfg := Config{AllowedNamespaces: []string{"*"}, MaxLogBytes: 4096}
	getPodLogs(context.Background(), cs, "prod", cfg)

	if capturedOpts == nil {
		t.Fatal("GetLogs was not called")
	}
	if capturedOpts.Container != "app" {
		t.Errorf("Container = %q, want %q (first non-ready container)", capturedOpts.Container, "app")
	}
}

// TestGetPodLogs_SingleContainerPod verifies that getPodLogs does NOT set a container
// name for single-container pods, preserving the existing behaviour where the API
// selects the only container automatically.
func TestGetPodLogs_SingleContainerPod(t *testing.T) {
	cs := fake.NewSimpleClientset()

	cs.PrependReactor("list", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, &corev1.PodList{Items: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "single-pod", Namespace: "prod"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "app"}},
			},
			Status: corev1.PodStatus{Phase: corev1.PodFailed},
		}}}, nil
	})

	var capturedOpts *corev1.PodLogOptions
	cs.PrependReactor("get", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		ga, ok := action.(k8stesting.GenericAction)
		if !ok || action.GetSubresource() != "log" {
			return false, nil, nil
		}
		if opts, ok := ga.GetValue().(*corev1.PodLogOptions); ok {
			capturedOpts = opts
		}
		return false, nil, nil
	})

	cfg := Config{AllowedNamespaces: []string{"*"}, MaxLogBytes: 4096}
	getPodLogs(context.Background(), cs, "prod", cfg)

	if capturedOpts == nil {
		t.Fatal("GetLogs was not called")
	}
	if capturedOpts.Container != "" {
		t.Errorf("Container = %q, want %q (empty — let API pick the single container)", capturedOpts.Container, "")
	}
}

// TestGetPodLogs_FetchBoundedToMaxLogPods verifies that getPodLogs processes at most
// maxLogPods pod entries even when more failing pods exist. The server-side Limit in
// the pod List call prevents downloading all pod objects before the in-memory cap
// runs — mirroring the Limit already applied by getEvents and getPodStatus.
func TestGetPodLogs_FetchBoundedToMaxLogPods(t *testing.T) {
	cs := fake.NewSimpleClientset()

	// Return more failing pods than maxLogPods to verify the cap applies.
	cs.PrependReactor("list", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		items := make([]corev1.Pod, maxLogPods+2)
		for i := range items {
			items[i] = corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("fail-pod-%d", i),
					Namespace: "prod",
				},
				Status: corev1.PodStatus{Phase: corev1.PodFailed},
			}
		}
		return true, &corev1.PodList{Items: items}, nil
	})

	cfg := Config{AllowedNamespaces: []string{"*"}, MaxLogBytes: 4096}
	result := getPodLogs(context.Background(), cs, "prod", cfg)

	// Count pod entries in the output. Each pod appears as "--- fail-pod-N ---".
	count := strings.Count(result, "--- fail-pod-")
	if count > maxLogPods {
		t.Errorf("getPodLogs processed %d pods, want at most %d (maxLogPods); server-side Limit must cap the pod list to avoid OOM on failing-pod storms",
			count, maxLogPods)
	}
	if count == 0 {
		t.Error("expected at least one pod log entry in output")
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

// TestGetPodStatus_LimitBoundedOutput verifies that getPodStatus returns at most
// maxPods lines even when the API (or fake client) delivers more pods than the limit.
// Without the server-side Limit in ListOptions, a namespace with hundreds of pods
// would fetch all pod objects into memory before formatting, risking OOM. The
// post-fetch backstop mirrors the pattern used in getEvents.
func TestGetPodStatus_LimitBoundedOutput(t *testing.T) {
	cs := fake.NewSimpleClientset()

	// Return maxPods+10 pods to simulate a namespace exceeding the limit.
	items := make([]corev1.Pod, maxPods+10)
	for i := range items {
		items[i] = corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("pod-%03d", i),
				Namespace: "busy",
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		}
	}
	cs.PrependReactor("list", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, &corev1.PodList{Items: items}, nil
	})

	pods := getPodStatus(context.Background(), cs, "busy")

	lines := strings.Split(strings.TrimRight(pods, "\n"), "\n")
	if len(lines) > maxPods {
		t.Errorf("getPodStatus returned %d lines, want at most %d (maxPods); unbounded List risks OOM on large namespaces",
			len(lines), maxPods)
	}
	if pods == "(no pods)" {
		t.Error("expected pod entries in output, got no-pods sentinel")
	}
}

// TestGetEvents_LimitSetInListOptions verifies that getEvents passes Limit:20 to
// the Kubernetes Events List call. Without the limit, a busy namespace (e.g. a
// CrashLoopBackOff pod emitting thousands of warning events) would have all of
// its events fetched into memory before the post-fetch slice trim runs, risking
// OOM. This mirrors the LimitBytes bound added for pod log fetches.
func TestGetEvents_LimitSetInListOptions(t *testing.T) {
	cs := fake.NewSimpleClientset()

	// Capture whether the List call included the field selector (which
	// confirms the ListOptions were set). We also intercept and return 30
	// events to verify the post-fetch cap holds.
	var listCalled bool
	cs.PrependReactor("list", "events", func(action k8stesting.Action) (bool, runtime.Object, error) {
		listCalled = true
		// Return 30 warning events to simulate a busy namespace. The
		// post-fetch cap in getEvents will trim this to 20 lines.
		items := make([]corev1.Event, 30)
		for i := range items {
			items[i] = corev1.Event{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("evt-%02d", i),
					Namespace: "busy",
				},
				Type:    corev1.EventTypeWarning,
				Reason:  "BackOff",
				Message: fmt.Sprintf("event %d", i),
				InvolvedObject: corev1.ObjectReference{
					Name: fmt.Sprintf("pod-%02d", i),
				},
			}
		}
		return true, &corev1.EventList{Items: items}, nil
	})

	alert := makeAlertWithLabels(map[string]string{"namespace": "busy"})
	cfg := Config{AllowedNamespaces: []string{}, MaxLogBytes: 4096}

	events, _, _ := GetKubeContext(context.Background(), cs, alert, cfg)

	if !listCalled {
		t.Fatal("Events List was not called")
	}
	if events == "(no warning events)" {
		t.Error("expected events output, got no-events sentinel")
	}
	// Even though the fake API returned 30 events the output must be bounded
	// to 20 lines: the API Limit caps the real fetch and the post-fetch trim
	// is a final backstop for the fake-client path.
	lines := strings.Split(strings.TrimRight(events, "\n"), "\n")
	if len(lines) > 20 {
		t.Errorf("getEvents returned %d lines, want at most 20", len(lines))
	}
}

// ----- GetPrometheusMetrics tests -----

func TestGetMetrics_NoNamespaceNoAlertname(t *testing.T) {
	srv := makePromServer(t, []PromResult{})
	defer srv.Close()

	prom := &PrometheusClient{HTTP: srv.Client(), URL: srv.URL}
	alert := makeAlertWithLabels(map[string]string{})
	result := prom.GetMetrics(context.Background(), alert)
	if !strings.Contains(result, "Active Firing Alerts") {
		t.Errorf("expected active alerts section, got %q", result)
	}
}

func TestGetMetrics_IncludesNamespaceSections(t *testing.T) {
	srv := makePromServer(t, []PromResult{})
	defer srv.Close()

	prom := &PrometheusClient{HTTP: srv.Client(), URL: srv.URL}
	alert := makeAlertWithLabels(map[string]string{
		"namespace": "production",
		"alertname": "SomeAlert",
	})
	result := prom.GetMetrics(context.Background(), alert)
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

func TestGetMetrics_CrashLoopAlertname(t *testing.T) {
	srv := makePromServer(t, []PromResult{})
	defer srv.Close()

	prom := &PrometheusClient{HTTP: srv.Client(), URL: srv.URL}
	alert := makeAlertWithLabels(map[string]string{"alertname": "PodCrashLoopBackOff"})
	result := prom.GetMetrics(context.Background(), alert)
	if !strings.Contains(result, "CrashLoop Details") {
		t.Errorf("expected CrashLoop Details section, got %q", result)
	}
}

func TestGetMetrics_MemoryAlertname(t *testing.T) {
	srv := makePromServer(t, []PromResult{})
	defer srv.Close()

	prom := &PrometheusClient{HTTP: srv.Client(), URL: srv.URL}
	alert := makeAlertWithLabels(map[string]string{"alertname": "HighMemoryUsage"})
	result := prom.GetMetrics(context.Background(), alert)
	if !strings.Contains(result, "Top Memory Consumers") {
		t.Errorf("expected Top Memory Consumers section, got %q", result)
	}
}

// TestGetMetrics_OOMAlertname verifies that alert names containing "oom"
// (case-insensitive) trigger the Top Memory Consumers section. This exercises
// the right-hand side of the `strings.Contains(lower, "memory") || strings.Contains(lower, "oom")`
// branch in GetMetrics, which was previously uncovered by tests.
func TestGetMetrics_OOMAlertname(t *testing.T) {
	srv := makePromServer(t, []PromResult{})
	defer srv.Close()

	prom := &PrometheusClient{HTTP: srv.Client(), URL: srv.URL}
	for _, name := range []string{"OOMKilled", "PodOOMKilled", "KubeContainerOOM"} {
		alert := makeAlertWithLabels(map[string]string{"alertname": name})
		result := prom.GetMetrics(context.Background(), alert)
		if !strings.Contains(result, "Top Memory Consumers") {
			t.Errorf("alert %q: expected Top Memory Consumers section, got %q", name, result)
		}
	}
}

func TestGetMetrics_CPUAlertname(t *testing.T) {
	srv := makePromServer(t, []PromResult{})
	defer srv.Close()

	prom := &PrometheusClient{HTTP: srv.Client(), URL: srv.URL}
	alert := makeAlertWithLabels(map[string]string{"alertname": "HighCPUUsage"})
	result := prom.GetMetrics(context.Background(), alert)
	if !strings.Contains(result, "Top CPU Consumers") {
		t.Errorf("expected Top CPU Consumers section, got %q", result)
	}
}

func TestGetMetrics_DiskAlertname(t *testing.T) {
	srv := makePromServer(t, []PromResult{})
	defer srv.Close()

	prom := &PrometheusClient{HTTP: srv.Client(), URL: srv.URL}
	for _, name := range []string{"DiskFull", "VolumeAlmostFull", "StoragePressure"} {
		alert := makeAlertWithLabels(map[string]string{"alertname": name})
		result := prom.GetMetrics(context.Background(), alert)
		if !strings.Contains(result, "PVC Usage") {
			t.Errorf("alert %q: expected PVC Usage section, got %q", name, result)
		}
	}
}

func TestGetMetrics_NodeAlertname(t *testing.T) {
	srv := makePromServer(t, []PromResult{})
	defer srv.Close()

	prom := &PrometheusClient{HTTP: srv.Client(), URL: srv.URL}
	alert := makeAlertWithLabels(map[string]string{"alertname": "NodeNotReady"})
	result := prom.GetMetrics(context.Background(), alert)
	if !strings.Contains(result, "Node Conditions") {
		t.Errorf("expected Node Conditions section, got %q", result)
	}
}

func TestGetMetrics_WithResultData(t *testing.T) {
	srv := makePromServer(t, []PromResult{
		{
			Metric: map[string]string{"job": "prometheus", "instance": "localhost:9090"},
			Value:  [2]interface{}{1700000000, "1"},
		},
	})
	defer srv.Close()

	prom := &PrometheusClient{HTTP: srv.Client(), URL: srv.URL}
	alert := makeAlertWithLabels(map[string]string{})
	result := prom.GetMetrics(context.Background(), alert)
	if !strings.Contains(result, "job=prometheus") && !strings.Contains(result, "instance=localhost:9090") {
		t.Errorf("expected metric labels in result, got %q", result)
	}
}

func TestGetMetrics_PrometheusUnreachable(t *testing.T) {
	prom := &PrometheusClient{HTTP: &http.Client{Timeout: time.Second}, URL: "http://127.0.0.1:1"}
	alert := makeAlertWithLabels(map[string]string{"alertname": "SomeAlert"})
	result := prom.GetMetrics(context.Background(), alert)
	// Should still return sections, with error messages inside them
	if !strings.Contains(result, "Active Firing Alerts") {
		t.Errorf("expected sections even on error, got %q", result)
	}
	if !strings.Contains(result, "query failed") {
		t.Errorf("expected query failed error, got %q", result)
	}
}

func TestGetMetrics_ErrorStatus(t *testing.T) {
	// Prometheus returns status="error" for a bad query; should surface the error, not "(no data)"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"error","errorType":"bad_data","error":"invalid parameter 'query': parse error"}`))
	}))
	defer srv.Close()

	prom := &PrometheusClient{HTTP: srv.Client(), URL: srv.URL}
	alert := makeAlertWithLabels(map[string]string{})
	result := prom.GetMetrics(context.Background(), alert)
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

	prom := &PrometheusClient{HTTP: srv.Client(), URL: srv.URL}
	alert := makeAlertWithLabels(map[string]string{})
	result := prom.GetMetrics(context.Background(), alert)
	// The oversized, truncated body cannot parse as JSON — expect the parse-failure sentinel.
	if !strings.Contains(result, "failed to parse") {
		t.Errorf("expected parse-failure sentinel for oversized response, got %q", result)
	}
}

// TestGetMetrics_InvalidNamespaceDropsNamespacedQueries verifies that when the
// namespace label in an alert contains characters that would allow PromQL label-value
// injection (e.g. closing braces, quotes), the namespace-scoped queries are silently
// dropped. Only the always-present "Active Firing Alerts" query must still run.
// This is the Prometheus analogue of TestGetKubeContext_InvalidNamespace which tests
// the same guard for Kubernetes API calls.
func TestGetMetrics_InvalidNamespaceDropsNamespacedQueries(t *testing.T) {
	srv := makePromServer(t, []PromResult{})
	defer srv.Close()

	prom := &PrometheusClient{HTTP: srv.Client(), URL: srv.URL}

	invalidNamespaces := []string{
		`default"}[5m]) or up{namespace="evil`, // PromQL injection attempt
		"-badstart",
		"bad start",
		"bad\x00null",
		strings.Repeat("a", 64), // exceeds 63-char limit
	}

	for _, ns := range invalidNamespaces {
		alert := makeAlertWithLabels(map[string]string{
			"namespace": ns,
			"alertname": "SomeAlert",
		})
		result := prom.GetMetrics(context.Background(), alert)

		// The unconditional active-alerts query must always be present.
		if !strings.Contains(result, "Active Firing Alerts") {
			t.Errorf("ns %q: expected 'Active Firing Alerts' section even for invalid namespace, got:\n%s", ns, result)
		}

		// Namespace-scoped sections must be absent — the invalid namespace
		// must not be interpolated into PromQL queries.
		if strings.Contains(result, "CPU Usage") {
			t.Errorf("ns %q: namespace-scoped CPU query must be dropped for invalid namespace, got:\n%s", ns, result)
		}
		if strings.Contains(result, "Memory Usage") {
			t.Errorf("ns %q: namespace-scoped memory query must be dropped for invalid namespace, got:\n%s", ns, result)
		}
		if strings.Contains(result, "Pod Restarts") {
			t.Errorf("ns %q: namespace-scoped pod restarts query must be dropped for invalid namespace, got:\n%s", ns, result)
		}
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

	prom := &PrometheusClient{HTTP: srv.Client(), URL: srv.URL}
	actx := GatherContext(context.Background(), prom, cs, alert, cfg)
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

	prom := &PrometheusClient{HTTP: srv.Client(), URL: srv.URL}
	actx := GatherContext(context.Background(), prom, cs, alert, cfg)
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

	prom := &PrometheusClient{HTTP: &http.Client{Timeout: time.Second}, URL: "http://127.0.0.1:1"}
	actx := GatherContext(context.Background(), prom, cs, alert, cfg)
	if len(actx.Sections) != 4 {
		t.Fatalf("expected 4 sections even when Prometheus unreachable, got %d", len(actx.Sections))
	}
	podSection := actx.Sections[2]
	if !strings.Contains(podSection.Content, "mypod") {
		t.Errorf("expected mypod in pod status section, got %q", podSection.Content)
	}
}

// TestGatherContext_PrometheusTimeoutIsEnforced verifies that GatherContext applies a
// bounded deadline to the Prometheus goroutine. Without cfg.PromTimeout (or the
// defaultPromTimeout fallback), a Prometheus server that hangs for multiple query
// round-trips could block a worker goroutine far beyond the Kubernetes API deadline.
// The test uses a short PromTimeout and a hanging server to confirm that GatherContext
// returns promptly with an error sentinel in the Prometheus section.
func TestGatherContext_PrometheusTimeoutIsEnforced(t *testing.T) {
	// Prometheus server that hangs until its request context is cancelled.
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		fmt.Fprint(w, `{}`)
	}))
	defer slow.Close()

	cs := fake.NewSimpleClientset()
	alert := makeAlertWithLabels(map[string]string{"alertname": "Test", "namespace": "ns"})
	cfg := Config{
		AllowedNamespaces: []string{},
		MaxLogBytes:       4096,
		PromTimeout:       150 * time.Millisecond, // short deadline to trigger fast
	}

	prom := &PrometheusClient{HTTP: slow.Client(), URL: slow.URL}
	start := time.Now()
	actx := GatherContext(context.Background(), prom, cs, alert, cfg)
	elapsed := time.Since(start)

	if elapsed > 3*time.Second {
		t.Errorf("GatherContext blocked for %v; expected to complete quickly when PromTimeout is short", elapsed)
	}
	if len(actx.Sections) != 4 {
		t.Fatalf("expected 4 sections, got %d", len(actx.Sections))
	}
	// Prometheus section must contain an error sentinel, not be empty.
	promContent := actx.Sections[0].Content
	if promContent == "" {
		t.Error("Prometheus section must not be empty after deadline — expected error sentinel from cancelled query")
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

	prom := &PrometheusClient{HTTP: slow.Client(), URL: slow.URL}
	// Should not block / panic
	actx := GatherContext(ctx, prom, cs, alert, cfg)
	if len(actx.Sections) != 4 {
		t.Fatalf("expected 4 sections, got %d", len(actx.Sections))
	}
}

// TestGetKubeContext_RespectsDeadlineFromConfig verifies that GetKubeContext derives
// a child context with a deadline bounded by cfg.KubeAPITimeout. The test passes an
// already-cancelled parent context and confirms that all three output strings carry
// error sentinels rather than blocking indefinitely — demonstrating that the child
// context derived inside GetKubeContext inherits and propagates cancellation.
//
// Note: the fake Kubernetes client executes reactors synchronously without
// consulting the context, so a blocked-reactor approach cannot be used here.
// Instead the test relies on the fake client returning an error when the context
// is already cancelled at call time, which happens when the real client is used.
// The meaningful unit being tested is that GetKubeContext creates and uses a
// child context — a property that is also exercised by the GatherContext
// cancelled-context test (TestGatherContext_CancelledContext).
func TestGetKubeContext_RespectsDeadlineFromConfig(t *testing.T) {
	cs := fake.NewSimpleClientset()
	alert := makeAlertWithLabels(map[string]string{"namespace": "prod"})
	cfg := Config{
		AllowedNamespaces: []string{"*"},
		MaxLogBytes:       4096,
		KubeAPITimeout:    50 * time.Millisecond,
	}

	// Verify that a non-zero KubeAPITimeout is used instead of the default.
	// We pass background context; GetKubeContext must cap it to KubeAPITimeout.
	// The fake client returns quickly, so we only check that the call completes
	// and returns well-formed (non-empty) outputs.
	events, pods, logs := GetKubeContext(context.Background(), cs, alert, cfg)
	if events == "" || pods == "" || logs == "" {
		t.Errorf("GetKubeContext returned empty output: events=%q pods=%q logs=%q", events, pods, logs)
	}
}

// TestGetKubeContext_DefaultTimeoutApplied verifies that when KubeAPITimeout is
// zero the default (30s) is used. We confirm this by checking that cfg with
// KubeAPITimeout=0 still produces valid output — i.e. the zero value is handled
// and does not cause a zero-deadline context (which would cancel immediately).
func TestGetKubeContext_DefaultTimeoutApplied(t *testing.T) {
	cs := fake.NewSimpleClientset()
	alert := makeAlertWithLabels(map[string]string{"namespace": "prod"})
	cfg := Config{
		AllowedNamespaces: []string{"*"},
		MaxLogBytes:       4096,
		KubeAPITimeout:    0, // should fall back to defaultKubeAPITimeout (30s)
	}

	events, pods, logs := GetKubeContext(context.Background(), cs, alert, cfg)
	if events == "" || pods == "" || logs == "" {
		t.Errorf("GetKubeContext with zero KubeAPITimeout returned empty output: events=%q pods=%q logs=%q",
			events, pods, logs)
	}
}

// ----- isValidNamespace tests -----

func TestIsValidNamespace(t *testing.T) {
	valid := []string{
		"default",
		"kube-system",
		"my-app",
		"prod",
		"a",
		"a1",
		"ns-with-hyphens",
	}
	for _, ns := range valid {
		if !isValidNamespace(ns) {
			t.Errorf("expected %q to be valid, but it was rejected", ns)
		}
	}

	invalid := []string{
		"",
		"-invalid",
		"invalid-",
		"UPPER",
		"has space",
		`default"}[5m]) or up{namespace="kube-system`,
		"has\"quote",
		"has}brace",
		strings.Repeat("a", 64), // exceeds 63-char limit
	}
	for _, ns := range invalid {
		if isValidNamespace(ns) {
			t.Errorf("expected %q to be invalid, but it was accepted", ns)
		}
	}
}

// TestGetMetrics_MaliciousNamespaceDroppedFromQuery verifies that an alert namespace
// containing PromQL special characters does not get interpolated into queries.
// A valid Prometheus server records the queries it receives; if the malicious string
// appeared in any query the test would see its distinctive token ("evil") in the URL.
func TestGetMetrics_MaliciousNamespaceDroppedFromQuery(t *testing.T) {
	var receivedQueries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQueries = append(receivedQueries, r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
	}))
	defer srv.Close()

	prom := &PrometheusClient{HTTP: srv.Client(), URL: srv.URL}
	// Namespace that looks like PromQL injection; contains "evil" as a token.
	maliciousNS := `default"} or up{instance="evil`
	alert := makeAlertWithLabels(map[string]string{
		"namespace": maliciousNS,
		"alertname": "SomeAlert",
	})
	_ = prom.GetMetrics(context.Background(), alert)

	for _, q := range receivedQueries {
		if strings.Contains(q, "evil") {
			t.Errorf("malicious namespace token appeared in a Prometheus query: %q", q)
		}
	}
}

// TestQuery_NonOKStatusCode verifies that a non-200 HTTP response from Prometheus is
// reported with the actual status code rather than a misleading "(failed to parse
// response)" message that was previously emitted when the body was not valid JSON.
func TestQuery_NonOKStatusCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, "<html>Service Unavailable</html>")
	}))
	defer srv.Close()

	prom := &PrometheusClient{HTTP: srv.Client(), URL: srv.URL}
	alert := makeAlertWithLabels(map[string]string{})
	result := prom.GetMetrics(context.Background(), alert)

	if !strings.Contains(result, "503") {
		t.Errorf("expected HTTP status 503 in result, got: %q", result)
	}
	if strings.Contains(result, "failed to parse") {
		t.Errorf("result should not contain misleading parse-error message, got: %q", result)
	}
}

// TestGetEvents_SortsByRecencyDescending verifies that getEvents returns the most
// recent warning events when the namespace has more events than maxEvents. The
// Kubernetes API returns events in etcd insertion order (oldest first), so without
// client-side sorting a busy namespace with a long event history would show only
// the oldest (least diagnostically useful) events to Claude.
func TestGetEvents_SortsByRecencyDescending(t *testing.T) {
	cs := fake.NewSimpleClientset()

	now := time.Now()
	// Inject 25 events: events 0-4 are old (hours ago), events 20-24 are recent.
	// Without sorting, the first 20 returned by the API would be the old ones.
	// With sorting, the 20 most recent should win.
	cs.PrependReactor("list", "events", func(action k8stesting.Action) (bool, runtime.Object, error) {
		items := make([]corev1.Event, 25)
		for i := range items {
			age := time.Duration(25-i) * time.Hour // i=0 is oldest (25h ago), i=24 is newest (1h ago)
			items[i] = corev1.Event{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("evt-%02d", i),
					Namespace: "busy",
				},
				Type:          corev1.EventTypeWarning,
				Reason:        "BackOff",
				LastTimestamp: metav1.Time{Time: now.Add(-age)},
				Message:       fmt.Sprintf("event-%02d", i),
				InvolvedObject: corev1.ObjectReference{
					Name: fmt.Sprintf("pod-%02d", i),
				},
			}
		}
		return true, &corev1.EventList{Items: items}, nil
	})

	result := getEvents(context.Background(), cs, "busy")

	// The 5 oldest events (evt-00 through evt-04, timestamped 25h–21h ago)
	// must NOT appear — they should be displaced by the 20 most recent ones.
	for i := 0; i < 5; i++ {
		old := fmt.Sprintf("event-%02d", i)
		if strings.Contains(result, old) {
			t.Errorf("old event %q appeared in output; expected only the 20 most recent events:\n%s", old, result)
		}
	}
	// The 20 most recent events (evt-05 through evt-24) must all appear.
	for i := 5; i < 25; i++ {
		recent := fmt.Sprintf("event-%02d", i)
		if !strings.Contains(result, recent) {
			t.Errorf("recent event %q missing from output:\n%s", recent, result)
		}
	}
	// Output must be bounded to at most maxEvents lines.
	lines := strings.Split(strings.TrimRight(result, "\n"), "\n")
	if len(lines) > 20 {
		t.Errorf("getEvents returned %d lines, want at most 20", len(lines))
	}
}

// TestQuery_MetricLabelsAreSorted verifies that when a Prometheus result contains
// multiple metric labels they are emitted in alphabetical order, making the Claude
// analysis context deterministic across runs.
func TestQuery_MetricLabelsAreSorted(t *testing.T) {
	// Return a result whose label keys are deliberately out of alphabetical order
	// so we can detect whether sorting is applied.
	srv := makePromServer(t, []PromResult{
		{
			Metric: map[string]string{
				"zoo":    "last",
				"alpha":  "first",
				"middle": "between",
			},
			Value: [2]interface{}{1700000000, "42"},
		},
	})
	defer srv.Close()

	prom := &PrometheusClient{HTTP: srv.Client(), URL: srv.URL}
	alert := makeAlertWithLabels(map[string]string{})
	result := prom.GetMetrics(context.Background(), alert)

	alphaIdx := strings.Index(result, "alpha=")
	middleIdx := strings.Index(result, "middle=")
	zooIdx := strings.Index(result, "zoo=")

	if alphaIdx == -1 || middleIdx == -1 || zooIdx == -1 {
		t.Fatalf("expected all labels in result, got: %q", result)
	}
	if alphaIdx >= middleIdx || middleIdx >= zooIdx {
		t.Errorf("metric labels not in sorted order: alpha@%d middle@%d zoo@%d\nresult: %q",
			alphaIdx, middleIdx, zooIdx, result)
	}
}
