package k8s

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
)

// TestQuery_RequestCreateError verifies that the query function returns the
// "(request error: ...)" sentinel when http.NewRequestWithContext fails. In
// practice this is triggered by a URL containing a control character.
func TestQuery_RequestCreateError(t *testing.T) {
	// A null byte in the URL makes NewRequestWithContext return an error.
	prom := &PrometheusClient{HTTP: http.DefaultClient, URL: "http://host\x00invalid"}
	result := prom.query(context.Background(), "up")
	if !strings.Contains(result, "request error") {
		t.Errorf("expected '(request error: ...)' for invalid URL, got: %s", result)
	}
}

// TestQuery_FailedToReadResponse verifies the "(failed to read response)" path.
// We use a server that sends a 200 header but then closes the connection before
// sending the body, which causes io.ReadAll to return an error.
func TestQuery_FailedToReadResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hijack the connection and close it immediately after writing headers.
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", 500)
			return
		}
		conn, _, _ := hj.Hijack()
		// Write a partial HTTP response (headers only, no body) then close.
		conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n")) //nolint:errcheck
		conn.Close()
	}))
	defer srv.Close()

	prom := &PrometheusClient{HTTP: srv.Client(), URL: srv.URL}
	result := prom.query(context.Background(), "up")
	if !strings.Contains(result, "failed to read response") {
		t.Errorf("expected '(failed to read response)', got: %s", result)
	}
}

// TestQuery_StatusSuccessWithNoError verifies the
// "(query error: status=...)" path — triggered when Prometheus returns a
// non-"success" status but no error message (e.g. status="warning").
func TestQuery_StatusWithNoErrorField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Return a response with a non-"success" status and no error field.
		w.Write([]byte(`{"status":"warning","data":{"resultType":"vector","result":[]}}`)) //nolint:errcheck
	}))
	defer srv.Close()

	prom := &PrometheusClient{HTTP: srv.Client(), URL: srv.URL}
	result := prom.query(context.Background(), "up")
	if !strings.Contains(result, "query error") {
		t.Errorf("expected '(query error: ...)' for non-success status without error, got: %s", result)
	}
	if !strings.Contains(result, "warning") {
		t.Errorf("expected status 'warning' in result, got: %s", result)
	}
}

// TestQuery_FailedToParseResponse verifies the "(failed to parse response)"
// path in query(). This is triggered when the Prometheus API returns HTTP 200
// but with a body that is not valid JSON (e.g. an HTML error page from a
// misconfigured reverse proxy). The test serves a plain-text body so that
// json.Unmarshal fails and the sentinel string is returned.
func TestQuery_FailedToParseResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<!DOCTYPE html><html><body>Bad Gateway</body></html>")) //nolint:errcheck
	}))
	defer srv.Close()

	prom := &PrometheusClient{HTTP: srv.Client(), URL: srv.URL}
	result := prom.query(context.Background(), "up")
	if result != "(failed to parse response)" {
		t.Errorf("expected '(failed to parse response)', got: %s", result)
	}
}

// TestGetEvents_ZeroLastTimestamp verifies that when an event has a zero
// LastTimestamp, the timestamp field in the output is an empty string rather
// than the zero-time representation. This exercises the else branch at context.go
// line 183 where ts is left as "" when LastTimestamp.IsZero() is true.
func TestGetEvents_ZeroLastTimestamp(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "events", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, &corev1.EventList{Items: []corev1.Event{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "evt-zero-ts", Namespace: "testns"},
				Type:       corev1.EventTypeWarning,
				Reason:     "BackOff",
				Message:    "zero timestamp event",
				InvolvedObject: corev1.ObjectReference{
					Name: "some-pod",
				},
				// LastTimestamp intentionally left as zero value.
			},
		}}, nil
	})

	alert := makeAlertWithLabels(map[string]string{"namespace": "testns"})
	cfg := Config{AllowedNamespaces: []string{}, MaxLogBytes: 4096}

	events, _, _ := GetKubeContext(context.Background(), cs, alert, cfg)
	if events == "(no warning events)" {
		t.Fatal("expected an event in output, got no-events sentinel")
	}
	if !strings.Contains(events, "BackOff") {
		t.Errorf("expected BackOff reason in output, got: %q", events)
	}
	if strings.Contains(events, "0001-01-01") {
		t.Errorf("zero timestamp should not appear as date string, got: %q", events)
	}
}

// TestGetEvents_NonZeroLastTimestamp verifies that when an event has a non-zero
// LastTimestamp, the RFC3339-formatted timestamp appears in the output. This
// covers the true branch of !e.LastTimestamp.IsZero() at context.go line 184.
func TestGetEvents_NonZeroLastTimestamp(t *testing.T) {
	evtTime := metav1.Now() // non-zero timestamp

	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "events", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, &corev1.EventList{Items: []corev1.Event{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "evt-with-ts", Namespace: "testns"},
				Type:       corev1.EventTypeWarning,
				Reason:     "OOMKilled",
				Message:    "container killed",
				InvolvedObject: corev1.ObjectReference{
					Name: "oom-pod",
				},
				LastTimestamp: evtTime,
			},
		}}, nil
	})

	alert := makeAlertWithLabels(map[string]string{"namespace": "testns"})
	cfg := Config{AllowedNamespaces: []string{}, MaxLogBytes: 4096}

	events, _, _ := GetKubeContext(context.Background(), cs, alert, cfg)
	if events == "(no warning events)" {
		t.Fatal("expected an event in output, got no-events sentinel")
	}
	if !strings.Contains(events, "OOMKilled") {
		t.Errorf("expected OOMKilled reason in output, got: %q", events)
	}
	// The output must contain a timestamp in RFC3339 format (starts with year 20xx).
	if !strings.Contains(events, "20") {
		t.Errorf("expected RFC3339 timestamp in output, got: %q", events)
	}
}

// TestGetEvents_ListError verifies that when the Kubernetes Events List call
// fails, getEvents returns the "(failed: ...)" sentinel rather than panicking
// or returning an empty string. This covers context.go:174.
func TestGetEvents_ListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "events", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("etcd unavailable")
	})

	alert := makeAlertWithLabels(map[string]string{"namespace": "testns"})
	cfg := Config{AllowedNamespaces: []string{}, MaxLogBytes: 4096}

	events, _, _ := GetKubeContext(context.Background(), cs, alert, cfg)
	if !strings.Contains(events, "failed") {
		t.Errorf("expected '(failed: ...)' for events list error, got: %q", events)
	}
	if !strings.Contains(events, "etcd unavailable") {
		t.Errorf("expected error detail in events output, got: %q", events)
	}
}

// TestGetPodLogs_NoLogsOnGetLogsError verifies the "--- podname --- (no logs)"
// sentinel that appears when GetLogs.DoRaw returns an error. This covers the
// getPodLogs error path at context.go line 296.
//
// The k8s fake client's GetLogs always succeeds (hardcoded fakerest.RESTClient
// ignores reactors), so we use a real kubernetes.NewForConfig client backed by
// an httptest server that returns HTTP 500 for log requests. This forces
// DoRaw to return an error and exercises the error branch.
func TestGetPodLogs_NoLogsOnGetLogsError(t *testing.T) {
	podListJSON := `{
		"apiVersion": "v1",
		"kind": "PodList",
		"metadata": {"resourceVersion": "1"},
		"items": [{
			"apiVersion": "v1",
			"kind": "Pod",
			"metadata": {"name": "errorpod", "namespace": "testns", "resourceVersion": "1"},
			"spec": {"containers": [{"name": "app", "image": "nginx"}]},
			"status": {"phase": "Failed"}
		}]
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/log") {
			http.Error(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","message":"internal error","code":500}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, podListJSON) //nolint:errcheck
	}))
	defer srv.Close()

	cs, err := kubernetes.NewForConfig(&rest.Config{Host: srv.URL})
	if err != nil {
		t.Fatalf("failed to create clientset: %v", err)
	}

	cfg := Config{AllowedNamespaces: []string{"*"}, MaxLogBytes: 4096}
	result := getPodLogs(context.Background(), cs, "testns", cfg)

	if !strings.Contains(result, "errorpod") {
		t.Errorf("expected pod name in output, got: %q", result)
	}
	if !strings.Contains(result, "(no logs)") {
		t.Errorf("expected '(no logs)' sentinel for DoRaw error, got: %q", result)
	}
}

// TestK8sHandleWebhook_BodyReadError verifies that when the request body read
// fails for a reason other than exceeding the size limit (e.g. a closed
// connection), the handler returns 400 Bad Request. This covers the "bad
// request" branch in handler.go:41.
func TestK8sHandleWebhook_BodyReadError(t *testing.T) {
	cfg := Config{
		WebhookSecret:   "test-secret",
		CooldownSeconds: 5,
	}
	cd := shared.NewCooldownManager()
	handler := HandleWebhook(cfg, cd, func(ap shared.AlertPayload) bool { return true }, nil)

	req := httptest.NewRequest("POST", "/webhook", &k8sErrorReader{})
	req.Header.Set("Authorization", "Bearer test-secret")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for body read error, got %d", rr.Code)
	}
}

// k8sErrorReader implements io.Reader and always returns an error that is NOT
// *http.MaxBytesError, triggering the generic "bad request" branch.
type k8sErrorReader struct{}

func (e *k8sErrorReader) Read(_ []byte) (int, error) {
	return 0, fmt.Errorf("simulated read failure")
}

// TestK8sProcessAlert_AnalysisFails_PublishFailureNotification verifies the
// pipeline path where analysis fails AND the failure notification publish also
// fails. The slog.Warn path at pipeline.go:52 must be hit without panicking.
func TestK8sProcessAlert_AnalysisFails_PublishFailureNotification(t *testing.T) {
	failPub := &mockPublisher{err: fmt.Errorf("ntfy unreachable")}
	cooldown := shared.NewCooldownManager()
	metrics := new(shared.AlertMetrics)

	deps := PipelineDeps{
		Analyzer:     &mockAnalyzer{err: fmt.Errorf("claude timeout")},
		Publishers:   []shared.Publisher{failPub},
		Cooldown:     cooldown,
		Metrics:      metrics,
		SystemPrompt: "test",
		GatherContext: func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext {
			return shared.AnalysisContext{}
		},
	}

	alert := shared.AlertPayload{
		Fingerprint: "fail-pub-k8s",
		Title:       "HighCPU",
		Severity:    "warning",
		Fields:      map[string]string{},
	}

	// Must not panic even when both analysis and failure-notification publish fail.
	ProcessAlert(context.Background(), deps, alert)

	if metrics.AlertsFailed.Load() != 1 {
		t.Errorf("AlertsFailed = %d, want 1", metrics.AlertsFailed.Load())
	}
	// The failure notification publish was attempted.
	if len(failPub.calls) != 1 {
		t.Errorf("expected 1 publish call (failure notification), got %d", len(failPub.calls))
	}
}

// TestGetKubeContext_GoroutinePanicRecovery verifies that an unexpected panic
// inside any of the three kube-context goroutines (events, pod status, pod logs)
// is caught by the per-goroutine recovery added in context.go and does NOT
// crash the program. The output for the panicking goroutine must contain the
// "(... panicked: ...)" sentinel rather than empty string, so callers know
// the data is unavailable. The other two goroutines must still return normally.
func TestGetKubeContext_GoroutinePanicRecovery(t *testing.T) {
	for _, resource := range []string{"events", "pods"} {
		resource := resource
		t.Run(resource+" panic", func(t *testing.T) {
			cs := fake.NewSimpleClientset()
			cs.PrependReactor("list", resource, func(action k8stesting.Action) (bool, runtime.Object, error) {
				panic("injected panic in " + resource + " list")
			})

			alert := makeAlertWithLabels(map[string]string{"namespace": "testns"})
			cfg := Config{AllowedNamespaces: []string{"*"}, MaxLogBytes: 4096}

			// Must not panic the test process.
			events, pods, _ := GetKubeContext(context.Background(), cs, alert, cfg)

			switch resource {
			case "events":
				if !strings.Contains(events, "panicked") {
					t.Errorf("events output should contain 'panicked' sentinel, got: %q", events)
				}
				// pods should still have a valid result (not empty, not panicked)
				if strings.Contains(pods, "panicked") {
					t.Errorf("pods output should not contain 'panicked' sentinel, got: %q", pods)
				}
			case "pods":
				if !strings.Contains(pods, "panicked") {
					t.Errorf("pods output should contain 'panicked' sentinel, got: %q", pods)
				}
				// events should still have a valid result
				if strings.Contains(events, "panicked") {
					t.Errorf("events output should not contain 'panicked' sentinel, got: %q", events)
				}
			}
		})
	}
}

// TestK8sProcessAlert_EmptyAnalysis_PublishFailureNotification verifies the
// empty-analysis branch of ProcessAlert when the failure notification also fails.
// This exercises the slog.Warn at pipeline.go:63.
func TestK8sProcessAlert_EmptyAnalysis_PublishFailureNotification(t *testing.T) {
	failPub := &mockPublisher{err: fmt.Errorf("ntfy down")}
	cooldown := shared.NewCooldownManager()
	metrics := new(shared.AlertMetrics)

	deps := PipelineDeps{
		Analyzer:     &mockAnalyzer{result: "", err: nil},
		Publishers:   []shared.Publisher{failPub},
		Cooldown:     cooldown,
		Metrics:      metrics,
		SystemPrompt: "test",
		GatherContext: func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext {
			return shared.AnalysisContext{}
		},
	}

	alert := shared.AlertPayload{
		Fingerprint: "empty-pub-k8s",
		Title:       "EmptyAlert",
		Severity:    "warning",
		Fields:      map[string]string{},
	}

	ProcessAlert(context.Background(), deps, alert)

	if metrics.AlertsFailed.Load() != 1 {
		t.Errorf("AlertsFailed = %d, want 1", metrics.AlertsFailed.Load())
	}
}

// TestGetPodStatus_ListError verifies that when the Kubernetes Pods List call
// fails, getPodStatus returns the "(failed: ...)" sentinel rather than panicking
// or returning an empty string. This covers the error path at context.go:279,
// the getPodStatus analogue of TestGetEvents_ListError and
// TestGetKubeContext_PodLogsAPIError — both peer context-gathering functions
// have their list-error paths explicitly asserted; this test fills the same
// coverage gap for getPodStatus.
// Using an empty AllowedNamespaces ensures getPodLogs returns early without
// calling Pods().List(), so the reactor is triggered solely by getPodStatus.
func TestGetPodStatus_ListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("etcd unavailable")
	})

	alert := makeAlertWithLabels(map[string]string{"namespace": "testns"})
	cfg := Config{AllowedNamespaces: []string{}, MaxLogBytes: 4096}

	_, pods, _ := GetKubeContext(context.Background(), cs, alert, cfg)
	if !strings.Contains(pods, "failed") {
		t.Errorf("expected '(failed: ...)' for pods list error, got: %q", pods)
	}
	if !strings.Contains(pods, "etcd unavailable") {
		t.Errorf("expected error detail in pods output, got: %q", pods)
	}
}

// TestGetEvents_EventTimeUsedWhenLastTimestampZero verifies that when an event
// has a zero LastTimestamp but a non-zero EventTime (the Kubernetes 1.14+
// canonical MicroTime field), the EventTime value is used for both sorting and
// display. This covers the `return e.EventTime.Time` branch in the eventTime
// helper (context.go) which was previously untested: the two existing timestamp
// tests either set LastTimestamp (TestGetEvents_NonZeroLastTimestamp) or leave
// both fields at zero (TestGetEvents_ZeroLastTimestamp). Kubernetes 1.14+
// populates EventTime and may leave LastTimestamp unset, so without this path
// the timestamp would silently appear as an empty string in the Claude prompt.
func TestGetEvents_EventTimeUsedWhenLastTimestampZero(t *testing.T) {
	evtTime := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)

	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "events", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, &corev1.EventList{Items: []corev1.Event{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "evt-microtime", Namespace: "testns"},
				Type:       corev1.EventTypeWarning,
				Reason:     "CrashLoopBackOff",
				Message:    "container kept crashing",
				InvolvedObject: corev1.ObjectReference{
					Name: "crash-pod",
				},
				EventTime: metav1.MicroTime{Time: evtTime}, // Kubernetes 1.14+ style
				// LastTimestamp intentionally left at zero value.
			},
		}}, nil
	})

	alert := makeAlertWithLabels(map[string]string{"namespace": "testns"})
	cfg := Config{AllowedNamespaces: []string{}, MaxLogBytes: 4096}

	events, _, _ := GetKubeContext(context.Background(), cs, alert, cfg)
	if events == "(no warning events)" {
		t.Fatal("expected an event in output, got no-events sentinel")
		return
	}
	if !strings.Contains(events, "CrashLoopBackOff") {
		t.Errorf("expected CrashLoopBackOff reason in output, got: %q", events)
	}
	// The EventTime must appear as a formatted RFC3339 timestamp — not empty.
	// If the eventTime helper returned zero instead of e.EventTime.Time, the
	// !t.IsZero() guard would produce an empty ts and "2026-01-15" would not
	// appear in the output.
	if !strings.Contains(events, "2026-01-15") {
		t.Errorf("expected EventTime date '2026-01-15' in output, got: %q", events)
	}
}
