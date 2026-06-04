package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
)

type publishCall struct {
	title    string
	priority string
	body     string
}

type mockPublisher struct {
	calls []publishCall
	err   error
}

func (m *mockPublisher) Publish(ctx context.Context, title, priority, body string) error {
	m.calls = append(m.calls, publishCall{title: title, priority: priority, body: body})
	return m.err
}

func (m *mockPublisher) Name() string { return "mock" }

// published returns the bodies published so far (backward-compatible helper).
func (m *mockPublisher) published() []string {
	out := make([]string, len(m.calls))
	for i, c := range m.calls {
		out[i] = c.body
	}
	return out
}

// mockToolRunnerAnalyzer satisfies BOTH shared.Analyzer and shared.ToolLoopRunner
// so a single mock can verify the policy-driven branch (Analyze for rounds==0,
// RunToolLoop otherwise). It records which method was called, with what model
// and rounds, so each test can assert on routing.
type mockToolRunnerAnalyzer struct {
	wantText  string
	wantErr   error
	gotModel  string
	gotRounds int
	calls     struct{ analyze, runToolLoop int }
}

func (m *mockToolRunnerAnalyzer) Reset() {
	m.gotModel = ""
	m.gotRounds = 0
	m.calls.analyze = 0
	m.calls.runToolLoop = 0
}

func (m *mockToolRunnerAnalyzer) Analyze(_ context.Context, _ shared.Severity, model, _, _ string) (string, error) {
	m.gotModel = model
	m.gotRounds = 0
	m.calls.analyze++
	return m.wantText, m.wantErr
}

func (m *mockToolRunnerAnalyzer) RunToolLoop(
	_ context.Context, _ shared.Severity, model, _, _ string,
	_ []anthropic.ToolUnionParam, rounds int,
	_ func(string, json.RawMessage) (string, error),
) (string, int, bool, error) {
	m.gotModel = model
	m.gotRounds = rounds
	m.calls.runToolLoop++
	return m.wantText, rounds, false, m.wantErr
}

// TestProcessAlert_UsesPolicyForModelAndRounds verifies that ProcessAlert reads
// model and round budget from the AnalysisPolicy (keyed on alert.SeverityLevel)
// instead of static PipelineDeps fields. When the policy yields rounds==0, it
// must take the static-only path (Analyze) instead of RunAgenticDiagnostics.
func TestProcessAlert_UsesPolicyForModelAndRounds(t *testing.T) {
	mock := &mockToolRunnerAnalyzer{wantText: "ok"}
	policy := &shared.AnalysisPolicy{
		DefaultModel:     "default-m",
		ModelOverrides:   map[shared.Severity]string{shared.SeverityCritical: "opus"},
		DefaultMaxRounds: 5,
		RoundsOverrides:  map[shared.Severity]int{shared.SeverityWarning: 0},
	}

	deps := PipelineDeps{
		ToolRunner:    mock,
		Analyzer:      mock,
		KubectlRunner: &fakeKubectlRunner{},
		Prom:          &fakePromQLQuerier{},
		Cooldown:      shared.NewCooldownManager(),
		Metrics:       shared.NewAlertMetrics(shared.NewPrometheusMetricsForTest(shared.ProductK8s)),
		Policy:        policy,
		GatherContext: func(context.Context, shared.AlertPayload) shared.AnalysisContext {
			return shared.AnalysisContext{}
		},
		Publishers: []shared.Publisher{&mockPublisher{}},
	}

	t.Run("critical_uses_opus_with_default_rounds", func(t *testing.T) {
		mock.Reset()
		ProcessAlert(context.Background(), deps, shared.AlertPayload{
			Fingerprint:   "fp1",
			SeverityLevel: shared.SeverityCritical,
			Source:        "k8s",
			Fields:        map[string]string{},
		})
		if mock.gotModel != "opus" {
			t.Errorf("model: got %q, want opus", mock.gotModel)
		}
		if mock.gotRounds != 5 {
			t.Errorf("rounds: got %d, want 5", mock.gotRounds)
		}
		if mock.calls.runToolLoop != 1 || mock.calls.analyze != 0 {
			t.Errorf("expected 1 RunToolLoop call, got %+v", mock.calls)
		}
	})

	t.Run("warning_with_zero_rounds_uses_Analyze", func(t *testing.T) {
		mock.Reset()
		ProcessAlert(context.Background(), deps, shared.AlertPayload{
			Fingerprint:   "fp2",
			SeverityLevel: shared.SeverityWarning,
			Source:        "k8s",
			Fields:        map[string]string{},
		})
		if mock.gotModel != "default-m" {
			t.Errorf("model: got %q, want default-m", mock.gotModel)
		}
		if mock.calls.analyze != 1 || mock.calls.runToolLoop != 0 {
			t.Errorf("expected 1 Analyze call, got %+v", mock.calls)
		}
	})
}

func TestProcessAlert_Success(t *testing.T) {
	pub := &mockPublisher{}
	metrics := shared.NewAlertMetrics(shared.NewPrometheusMetricsForTest(shared.ProductK8s))

	deps := PipelineDeps{
		ToolRunner: &fakeToolLoopRunner{
			driver: func(_ func(string, json.RawMessage) (string, error)) (string, error) {
				return "root cause: OOM", nil
			},
		},
		KubectlRunner: &fakeKubectlRunner{},
		Prom:          &fakePromQLQuerier{},
		Publishers:    []shared.Publisher{pub},
		Cooldown:      shared.NewCooldownManager(),
		Metrics:       metrics,
		Policy:        &shared.AnalysisPolicy{DefaultModel: "test-model", DefaultMaxRounds: 10},
		GatherContext: func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext {
			return shared.AnalysisContext{
				Sections: []shared.ContextSection{{Name: "Test", Content: "data"}},
			}
		},
	}

	alert := shared.AlertPayload{
		Fingerprint: "abc",
		Title:       "HighCPU",
		Severity:    "critical",
		Source:      "k8s",
		Fields:      map[string]string{"status": "firing", "label:namespace": "monitoring"},
	}

	ProcessAlert(context.Background(), deps, alert)

	if int64(testutil.ToFloat64(metrics.Prom.AlertsProcessed.WithLabelValues("unknown"))) != 1 {
		t.Errorf("AlertsProcessed = %d, want 1", int64(testutil.ToFloat64(metrics.Prom.AlertsProcessed.WithLabelValues("unknown"))))
	}
	bodies := pub.published()
	if len(bodies) != 1 {
		t.Fatalf("published %d, want 1", len(bodies))
	}
	if bodies[0] != "root cause: OOM" {
		t.Errorf("published body = %q", bodies[0])
	}
}

func TestProcessAlert_AnalysisFails(t *testing.T) {
	pub := &mockPublisher{}
	cooldown := shared.NewCooldownManager()
	metrics := shared.NewAlertMetrics(shared.NewPrometheusMetricsForTest(shared.ProductK8s))

	deps := PipelineDeps{
		ToolRunner: &fakeToolLoopRunner{
			driver: func(_ func(string, json.RawMessage) (string, error)) (string, error) {
				return "", context.DeadlineExceeded
			},
		},
		KubectlRunner: &fakeKubectlRunner{},
		Prom:          &fakePromQLQuerier{},
		Publishers:    []shared.Publisher{pub},
		Cooldown:      cooldown,
		Metrics:       metrics,
		Policy:        &shared.AnalysisPolicy{DefaultModel: "test-model", DefaultMaxRounds: 10},
		GatherContext: func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext {
			return shared.AnalysisContext{}
		},
	}

	alert := shared.AlertPayload{Fingerprint: "abc", Title: "Test", Severity: "warning", Fields: map[string]string{}}
	ProcessAlert(context.Background(), deps, alert)

	if int64(testutil.ToFloat64(metrics.Prom.AlertsFailed)) != 1 {
		t.Errorf("AlertsFailed = %d, want 1", int64(testutil.ToFloat64(metrics.Prom.AlertsFailed)))
	}
	// Cooldown should be cleared on failure
	if !cooldown.CheckAndSet("abc", 300*1e9) {
		t.Error("cooldown not cleared after failure")
	}
}

// TestProcessAlert_PublishFails verifies that when PublishAll returns an error
// in the post-API phase (analysis succeeded, publish failed), AlertsFailed is
// incremented and the cooldown is KEPT — re-running an expensive analysis just
// because ntfy is unavailable wastes API spend. ntfy-failure is logged
// separately and surfaced via the ntfy_publish_errors_total counter.
func TestProcessAlert_PublishFails(t *testing.T) {
	pub := &mockPublisher{err: fmt.Errorf("ntfy unavailable")}
	cooldown := shared.NewCooldownManager()
	metrics := shared.NewAlertMetrics(shared.NewPrometheusMetricsForTest(shared.ProductK8s))

	deps := PipelineDeps{
		ToolRunner: &fakeToolLoopRunner{
			driver: func(_ func(string, json.RawMessage) (string, error)) (string, error) {
				return "some analysis", nil
			},
		},
		KubectlRunner: &fakeKubectlRunner{},
		Prom:          &fakePromQLQuerier{},
		Publishers:    []shared.Publisher{pub},
		Cooldown:      cooldown,
		Metrics:       metrics,
		Policy:        &shared.AnalysisPolicy{DefaultModel: "test-model", DefaultMaxRounds: 10},
		GatherContext: func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext {
			return shared.AnalysisContext{}
		},
	}

	// Pre-set cooldown so we can verify it is NOT cleared after the post-API publish failure.
	if !cooldown.CheckAndSet("fp1", time.Hour) {
		t.Fatal("failed to set cooldown")
	}
	alert := shared.AlertPayload{Fingerprint: "fp1", Title: "DiskFull", Severity: "critical", Fields: map[string]string{}}
	ProcessAlert(context.Background(), deps, alert)

	if int64(testutil.ToFloat64(metrics.Prom.AlertsFailed)) != 1 {
		t.Errorf("AlertsFailed = %d, want 1", int64(testutil.ToFloat64(metrics.Prom.AlertsFailed)))
	}
	if int64(testutil.ToFloat64(metrics.Prom.AlertsProcessed.WithLabelValues("unknown"))) != 0 {
		t.Errorf("AlertsProcessed = %d, want 0", int64(testutil.ToFloat64(metrics.Prom.AlertsProcessed.WithLabelValues("unknown"))))
	}
	// Post-API failure: cooldown must NOT be cleared.
	if cooldown.CheckAndSet("fp1", time.Second) {
		t.Error("cooldown was cleared after post-API publish failure; want kept")
	}
}

// TestProcessAlert_PublishFails_RecordsPrometheusCounter verifies that when
// PublishAll returns an error and Prom is non-nil, the ntfy_publish_errors_total
// Prometheus counter is incremented. The existing TestProcessAlert_PublishFails
// uses shared.NewAlertMetrics(shared.NewPrometheusMetricsForTest(shared.ProductK8s)) (Prom == nil) so RecordNtfyPublishError is a
// no-op there; this test exercises the non-nil path.
func TestProcessAlert_PublishFails_RecordsPrometheusCounter(t *testing.T) {
	pub := &mockPublisher{err: fmt.Errorf("ntfy unavailable")}
	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetricsForTest(shared.ProductK8s)}

	deps := PipelineDeps{
		ToolRunner: &fakeToolLoopRunner{
			driver: func(_ func(string, json.RawMessage) (string, error)) (string, error) {
				return "some analysis", nil
			},
		},
		KubectlRunner: &fakeKubectlRunner{},
		Prom:          &fakePromQLQuerier{},
		Publishers:    []shared.Publisher{pub},
		Cooldown:      shared.NewCooldownManager(),
		Metrics:       metrics,
		Policy:        &shared.AnalysisPolicy{DefaultModel: "test-model", DefaultMaxRounds: 10},
		GatherContext: func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext {
			return shared.AnalysisContext{}
		},
	}

	alert := shared.AlertPayload{
		Fingerprint: "fp-prom",
		Title:       "DiskFull",
		Severity:    "critical",
		Source:      "k8s",
		Fields:      map[string]string{},
	}
	ProcessAlert(context.Background(), deps, alert)

	got := testutil.ToFloat64(metrics.Prom.NtfyPublishErrors)
	if got != 1 {
		t.Errorf("ntfy_publish_errors_total{source=\"k8s\"} = %v, want 1", got)
	}
}

// TestProcessAlert_AnalysisFails_RecordsClaudeAPIErrorCounter verifies that
// when RunAgenticDiagnostics returns an error and Prom is non-nil, the
// claude_api_errors_total Prometheus counter is incremented. The counter is
// used to alert on sustained Claude API outages; without this call the metric
// is permanently zero.
func TestProcessAlert_AnalysisFails_RecordsClaudeAPIErrorCounter(t *testing.T) {
	pub := &mockPublisher{}
	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetricsForTest(shared.ProductK8s)}

	deps := PipelineDeps{
		ToolRunner: &fakeToolLoopRunner{
			driver: func(_ func(string, json.RawMessage) (string, error)) (string, error) {
				return "", context.DeadlineExceeded
			},
		},
		KubectlRunner: &fakeKubectlRunner{},
		Prom:          &fakePromQLQuerier{},
		Publishers:    []shared.Publisher{pub},
		Cooldown:      shared.NewCooldownManager(),
		Metrics:       metrics,
		Policy:        &shared.AnalysisPolicy{DefaultModel: "test-model", DefaultMaxRounds: 10},
		GatherContext: func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext {
			return shared.AnalysisContext{}
		},
	}

	alert := shared.AlertPayload{
		Fingerprint: "fp-claude-err",
		Title:       "HighCPU",
		Severity:    "critical",
		Source:      "k8s",
		Fields:      map[string]string{},
	}
	ProcessAlert(context.Background(), deps, alert)

	got := testutil.ToFloat64(metrics.Prom.ClaudeAPIErrors)
	if got != 1 {
		t.Errorf("claude_api_errors_total{source=\"k8s\"} = %v, want 1", got)
	}
}

// TestProcessAlert_EmptyAnalysis verifies that when RunAgenticDiagnostics
// returns ("", nil) — which can happen if Claude produces no text content
// blocks — the pipeline treats it as a failure: cooldown is cleared and
// AlertsFailed is incremented.
func TestProcessAlert_EmptyAnalysis(t *testing.T) {
	pub := &mockPublisher{}
	cooldown := shared.NewCooldownManager()
	metrics := shared.NewAlertMetrics(shared.NewPrometheusMetricsForTest(shared.ProductK8s))

	deps := PipelineDeps{
		ToolRunner: &fakeToolLoopRunner{
			driver: func(_ func(string, json.RawMessage) (string, error)) (string, error) {
				return "", nil
			},
		},
		KubectlRunner: &fakeKubectlRunner{},
		Prom:          &fakePromQLQuerier{},
		Publishers:    []shared.Publisher{pub},
		Cooldown:      cooldown,
		Metrics:       metrics,
		Policy:        &shared.AnalysisPolicy{DefaultModel: "test-model", DefaultMaxRounds: 10},
		GatherContext: func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext {
			return shared.AnalysisContext{}
		},
	}

	alert := shared.AlertPayload{Fingerprint: "fp-empty", Title: "EmptyAlert", Severity: "warning", Fields: map[string]string{}}
	ProcessAlert(context.Background(), deps, alert)

	if int64(testutil.ToFloat64(metrics.Prom.AlertsFailed)) != 1 {
		t.Errorf("AlertsFailed = %d, want 1", int64(testutil.ToFloat64(metrics.Prom.AlertsFailed)))
	}
	if int64(testutil.ToFloat64(metrics.Prom.AlertsProcessed.WithLabelValues("unknown"))) != 0 {
		t.Errorf("AlertsProcessed = %d, want 0", int64(testutil.ToFloat64(metrics.Prom.AlertsProcessed.WithLabelValues("unknown"))))
	}
	// Cooldown must be cleared so the next webhook can re-trigger analysis.
	if !cooldown.CheckAndSet("fp-empty", 300*1e9) {
		t.Error("cooldown not cleared after empty-analysis failure")
	}
	// A failure notification must have been published.
	if len(pub.calls) != 1 {
		t.Fatalf("expected 1 publish call, got %d", len(pub.calls))
	}
	if pub.calls[0].priority != "5" {
		t.Errorf("failure notification priority = %q, want %q", pub.calls[0].priority, "5")
	}
}

// TestProcessAlert_PanicClearsCooldown verifies that a panic inside ProcessAlert
// (e.g. a nil-pointer in context gathering) clears the cooldown so the next
// webhook can trigger a retry rather than being silently dropped for the TTL.
func TestProcessAlert_PanicClearsCooldown(t *testing.T) {
	pub := &mockPublisher{}
	cooldown := shared.NewCooldownManager()
	metrics := shared.NewAlertMetrics(shared.NewPrometheusMetricsForTest(shared.ProductK8s))

	deps := PipelineDeps{
		ToolRunner: &fakeToolLoopRunner{
			driver: func(_ func(string, json.RawMessage) (string, error)) (string, error) {
				panic("simulated analysis panic")
			},
		},
		KubectlRunner: &fakeKubectlRunner{},
		Prom:          &fakePromQLQuerier{},
		Publishers:    []shared.Publisher{pub},
		Cooldown:      cooldown,
		Metrics:       metrics,
		Policy:        &shared.AnalysisPolicy{DefaultModel: "test-model", DefaultMaxRounds: 10},
		GatherContext: func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext {
			return shared.AnalysisContext{}
		},
	}

	alert := shared.AlertPayload{Fingerprint: "panic-fp", Title: "Test", Severity: "warning", Fields: map[string]string{}}

	// ProcessAlert re-panics after clearing cooldown; recover here so the test doesn't fail.
	func() {
		defer func() { recover() }()
		ProcessAlert(context.Background(), deps, alert)
	}()

	// Cooldown must be cleared so the next webhook can re-trigger analysis.
	if !cooldown.CheckAndSet("panic-fp", 300*1e9) {
		t.Error("cooldown not cleared after panic")
	}
	if int64(testutil.ToFloat64(metrics.Prom.AlertsFailed)) != 1 {
		t.Errorf("AlertsFailed = %d, want 1", int64(testutil.ToFloat64(metrics.Prom.AlertsFailed)))
	}
}

// TestProcessAlert_PriorityMapping verifies the severity → ntfy priority table.
// Priority is keyed on alert.SeverityLevel (the normalised enum), not the raw
// alert.Severity label, so Alertmanager severity values like "page" (which
// normalises to SeverityCritical) and "notice" (→ SeverityWarning) produce the
// correct priority even though they do not appear literally in the map.
func TestProcessAlert_PriorityMapping(t *testing.T) {
	cases := []struct {
		name          string
		severityLevel shared.Severity
		rawSeverity   string // Alertmanager label value; does NOT affect priority
		want          string
	}{
		{"critical", shared.SeverityCritical, "critical", "5"},
		{"warning", shared.SeverityWarning, "warning", "4"},
		{"info", shared.SeverityInfo, "info", "2"},
		{"unknown", shared.SeverityUnknown, "unknown", "3"},
		// Non-standard Alertmanager labels that normalise to known severities.
		// Previously these fell through to the default "3" because the raw label
		// ("page", "notice") was used for the map lookup instead of SeverityLevel.
		{"page_is_critical", shared.SeverityCritical, "page", "5"},
		{"notice_is_warning", shared.SeverityWarning, "notice", "4"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			pub := &mockPublisher{}
			metrics := shared.NewAlertMetrics(shared.NewPrometheusMetricsForTest(shared.ProductK8s))

			deps := PipelineDeps{
				ToolRunner: &fakeToolLoopRunner{
					driver: func(_ func(string, json.RawMessage) (string, error)) (string, error) {
						return "analysis", nil
					},
				},
				KubectlRunner: &fakeKubectlRunner{},
				Prom:          &fakePromQLQuerier{},
				Publishers:    []shared.Publisher{pub},
				Cooldown:      shared.NewCooldownManager(),
				Metrics:       metrics,
				Policy:        &shared.AnalysisPolicy{DefaultModel: "test-model", DefaultMaxRounds: 10},
				GatherContext: func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext {
					return shared.AnalysisContext{}
				},
			}

			alert := shared.AlertPayload{
				Fingerprint:   "fp-" + tc.name,
				Title:         "TestAlert",
				Severity:      tc.rawSeverity,
				SeverityLevel: tc.severityLevel,
				Fields:        map[string]string{},
			}
			ProcessAlert(context.Background(), deps, alert)

			if len(pub.calls) != 1 {
				t.Fatalf("expected 1 publish call, got %d", len(pub.calls))
			}
			if pub.calls[0].priority != tc.want {
				t.Errorf("priority = %q, want %q", pub.calls[0].priority, tc.want)
			}
		})
	}
}

// TestProcessAlert_StartsAtInPrompt verifies that the startsAt timestamp is
// included in the user prompt passed to the analyzer. The timestamp tells Claude
// when the alert fired, which is useful for correlating with deployments or
// other events that happened around the same time.
func TestProcessAlert_StartsAtInPrompt(t *testing.T) {
	runner := &fakeToolLoopRunner{
		driver: func(_ func(string, json.RawMessage) (string, error)) (string, error) {
			return "analysis", nil
		},
	}
	pub := &mockPublisher{}
	metrics := shared.NewAlertMetrics(shared.NewPrometheusMetricsForTest(shared.ProductK8s))

	deps := PipelineDeps{
		ToolRunner:    runner,
		KubectlRunner: &fakeKubectlRunner{},
		Prom:          &fakePromQLQuerier{},
		Publishers:    []shared.Publisher{pub},
		Cooldown:      shared.NewCooldownManager(),
		Metrics:       metrics,
		Policy:        &shared.AnalysisPolicy{DefaultModel: "test-model", DefaultMaxRounds: 10},
		GatherContext: func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext {
			return shared.AnalysisContext{}
		},
	}

	alert := shared.AlertPayload{
		Fingerprint: "fp-startsat",
		Title:       "HighCPU",
		Severity:    "warning",
		Fields: map[string]string{
			"status":          "firing",
			"label:namespace": "production",
			"startsAt":        "2024-01-15T03:00:00Z",
		},
	}
	ProcessAlert(context.Background(), deps, alert)

	// Lock down the full alert-header prefix verbatim. Any future refactor
	// that drops alertname/status/severity/namespace/StartsAt or reorders
	// them will now fail this test.
	wantPrefix := "## Alert: HighCPU\n" +
		"- Status: firing\n" +
		"- Severity: warning\n" +
		"- Namespace: production\n" +
		"- StartsAt: 2024-01-15T03:00:00Z\n" +
		"\n"
	if !strings.HasPrefix(runner.captured, wantPrefix) {
		t.Errorf("user prompt header mismatch.\nwant prefix:\n%q\ngot:\n%q", wantPrefix, runner.captured)
	}
}

// TestProcessAlert_FailureBodySanitizesTitle verifies that embedded control
// characters in alert.Title do not appear in the failure notification body.
// A crafted webhook with a title like "Alert\n## Injected" could otherwise
// corrupt the ntfy notification body since NtfyPublisher.Publish does not
// sanitize the body parameter (only the title header).
func TestProcessAlert_FailureBodySanitizesTitle(t *testing.T) {
	pub := &mockPublisher{}
	metrics := shared.NewAlertMetrics(shared.NewPrometheusMetricsForTest(shared.ProductK8s))

	deps := PipelineDeps{
		ToolRunner: &fakeToolLoopRunner{
			driver: func(_ func(string, json.RawMessage) (string, error)) (string, error) {
				return "", fmt.Errorf("api error")
			},
		},
		KubectlRunner: &fakeKubectlRunner{},
		Prom:          &fakePromQLQuerier{},
		Publishers:    []shared.Publisher{pub},
		Cooldown:      shared.NewCooldownManager(),
		Metrics:       metrics,
		Policy:        &shared.AnalysisPolicy{DefaultModel: "test-model", DefaultMaxRounds: 10},
		GatherContext: func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext {
			return shared.AnalysisContext{}
		},
	}

	alert := shared.AlertPayload{
		Fingerprint: "fp-ctrl",
		Title:       "HighCPU\n## Injected Section",
		Severity:    "warning",
		Fields:      map[string]string{},
	}
	ProcessAlert(context.Background(), deps, alert)

	if len(pub.calls) != 1 {
		t.Fatalf("expected 1 publish call, got %d", len(pub.calls))
	}
	if strings.Contains(pub.calls[0].body, "\n## Injected Section") {
		t.Errorf("control character from title leaked into failure body: %q", pub.calls[0].body)
	}
	if !strings.Contains(pub.calls[0].body, "HighCPU") {
		t.Errorf("sanitized title should still appear in body, got: %q", pub.calls[0].body)
	}
}

// TestProcessAlert_FailureBodyRedactsErrorMessage verifies that secrets in the
// analysis error message are redacted before appearing in the failure
// notification body. RedactSecrets must run before SanitizeAlertField so that
// redaction patterns can match the raw error text.
func TestProcessAlert_FailureBodyRedactsErrorMessage(t *testing.T) {
	pub := &mockPublisher{}
	metrics := shared.NewAlertMetrics(shared.NewPrometheusMetricsForTest(shared.ProductK8s))
	mock := &mockToolRunnerAnalyzer{
		wantErr: fmt.Errorf("dial failed: token=supersecretvalue123"),
	}

	deps := PipelineDeps{
		Analyzer:      mock,
		ToolRunner:    mock,
		KubectlRunner: &fakeKubectlRunner{},
		Prom:          &fakePromQLQuerier{},
		Publishers:    []shared.Publisher{pub},
		Cooldown:      shared.NewCooldownManager(),
		Metrics:       metrics,
		Policy:        &shared.AnalysisPolicy{DefaultModel: "test-model", DefaultMaxRounds: 0},
		GatherContext: func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext {
			return shared.AnalysisContext{}
		},
	}

	alert := shared.AlertPayload{
		Fingerprint: "fp-redact-err",
		Title:       "HighCPU",
		Severity:    "warning",
		Fields:      map[string]string{},
	}
	ProcessAlert(context.Background(), deps, alert)

	if len(pub.calls) != 1 {
		t.Fatalf("expected 1 publish call, got %d", len(pub.calls))
	}
	if strings.Contains(pub.calls[0].body, "supersecretvalue123") {
		t.Errorf("secret leaked into failure body: %q", pub.calls[0].body)
	}
	if !strings.Contains(pub.calls[0].body, "[REDACTED]") {
		t.Errorf("expected [REDACTED] in failure body, got: %q", pub.calls[0].body)
	}
}

// TestProcessAlert_FailureTitleSanitizesTitle verifies that embedded control
// characters in alert.Title do not appear in the notification title for failed
// analyses ("Analysis FAILED: <title>"). TestProcessAlert_FailureBodySanitizesTitle
// already guards the body; this companion test pins the title field so that any
// regression in the SanitizeAlertField extraction point is caught regardless of
// which PublishAll argument carries the tainted string.
func TestProcessAlert_FailureTitleSanitizesTitle(t *testing.T) {
	pub := &mockPublisher{}
	metrics := shared.NewAlertMetrics(shared.NewPrometheusMetricsForTest(shared.ProductK8s))
	mock := &mockToolRunnerAnalyzer{wantErr: fmt.Errorf("api error")}

	deps := PipelineDeps{
		Analyzer:      mock,
		ToolRunner:    mock,
		KubectlRunner: &fakeKubectlRunner{},
		Prom:          &fakePromQLQuerier{},
		Publishers:    []shared.Publisher{pub},
		Cooldown:      shared.NewCooldownManager(),
		Metrics:       metrics,
		Policy:        &shared.AnalysisPolicy{DefaultModel: "test-model", DefaultMaxRounds: 0},
		GatherContext: func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext {
			return shared.AnalysisContext{}
		},
	}

	alert := shared.AlertPayload{
		Fingerprint: "fp-title-ctrl-fail",
		Title:       "HighCPU\n## Injected Section",
		Severity:    "warning",
		Fields:      map[string]string{},
	}
	ProcessAlert(context.Background(), deps, alert)

	if len(pub.calls) != 1 {
		t.Fatalf("expected 1 publish call, got %d", len(pub.calls))
	}
	// The newline must be stripped — a raw "\n" in an HTTP title header is
	// invalid (RFC 7230 §3.2.6). SanitizeAlertField at extraction (alertname :=
	// shared.SanitizeAlertField(alert.Title)) protects all downstream uses.
	if strings.ContainsRune(pub.calls[0].title, '\n') {
		t.Errorf("newline from alert.Title leaked into failure notification title: %q", pub.calls[0].title)
	}
	if !strings.Contains(pub.calls[0].title, "HighCPU") {
		t.Errorf("sanitized title should still appear in notification title, got: %q", pub.calls[0].title)
	}
}

// TestProcessAlert_SuccessTitleSanitizesTitle verifies that embedded control
// characters in alert.Title do not appear in the notification title for
// successful analyses ("Analysis: <title>"). Mirrors
// TestProcessAlert_FailureTitleSanitizesTitle for the success path.
func TestProcessAlert_SuccessTitleSanitizesTitle(t *testing.T) {
	pub := &mockPublisher{}
	metrics := shared.NewAlertMetrics(shared.NewPrometheusMetricsForTest(shared.ProductK8s))
	mock := &mockToolRunnerAnalyzer{wantText: "root cause: OOM"}

	deps := PipelineDeps{
		Analyzer:      mock,
		ToolRunner:    mock,
		KubectlRunner: &fakeKubectlRunner{},
		Prom:          &fakePromQLQuerier{},
		Publishers:    []shared.Publisher{pub},
		Cooldown:      shared.NewCooldownManager(),
		Metrics:       metrics,
		Policy:        &shared.AnalysisPolicy{DefaultModel: "test-model", DefaultMaxRounds: 0},
		GatherContext: func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext {
			return shared.AnalysisContext{}
		},
	}

	alert := shared.AlertPayload{
		Fingerprint: "fp-success-ctrl",
		Title:       "HighCPU\n## Injected Section",
		Severity:    "critical",
		Fields:      map[string]string{},
	}
	ProcessAlert(context.Background(), deps, alert)

	if len(pub.calls) != 1 {
		t.Fatalf("expected 1 publish call, got %d", len(pub.calls))
	}
	if strings.Contains(pub.calls[0].title, "\n") {
		t.Errorf("newline from alert.Title leaked into success notification title: %q", pub.calls[0].title)
	}
	if !strings.Contains(pub.calls[0].title, "HighCPU") {
		t.Errorf("sanitized title should appear in success notification title, got: %q", pub.calls[0].title)
	}
}

// TestProcessAlert_PromptSanitizesNamespace verifies that embedded control
// characters in the label:namespace field are stripped from the user prompt
// passed to the analyzer. alertname and namespace are sanitized at extraction
// (not inline in the fmt.Sprintf), so this test confirms the invariant holds
// for namespace after the extraction-point sanitization refactor.
func TestProcessAlert_PromptSanitizesNamespace(t *testing.T) {
	runner := &fakeToolLoopRunner{
		driver: func(_ func(string, json.RawMessage) (string, error)) (string, error) {
			return "analysis", nil
		},
	}
	pub := &mockPublisher{}
	metrics := shared.NewAlertMetrics(shared.NewPrometheusMetricsForTest(shared.ProductK8s))

	deps := PipelineDeps{
		ToolRunner:    runner,
		KubectlRunner: &fakeKubectlRunner{},
		Prom:          &fakePromQLQuerier{},
		Publishers:    []shared.Publisher{pub},
		Cooldown:      shared.NewCooldownManager(),
		Metrics:       metrics,
		Policy:        &shared.AnalysisPolicy{DefaultModel: "test-model", DefaultMaxRounds: 10},
		GatherContext: func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext {
			return shared.AnalysisContext{}
		},
	}

	alert := shared.AlertPayload{
		Fingerprint: "fp-ns-ctrl",
		Title:       "HighCPU",
		Severity:    "warning",
		Fields: map[string]string{
			"label:namespace": "production\n## Injected Section",
		},
	}
	ProcessAlert(context.Background(), deps, alert)

	// Lock down the full alert-header prefix verbatim. Any future refactor
	// that drops alertname/status/severity/namespace/StartsAt or reorders
	// them will now fail this test. The namespace fixture is
	// "production\n## Injected Section"; SanitizeAlertField strips only the
	// leading \n control character, yielding "production## Injected Section".
	// status and startsAt are absent from the fixture, so they are empty strings.
	wantPrefix := "## Alert: HighCPU\n" +
		"- Status: \n" +
		"- Severity: warning\n" +
		"- Namespace: production## Injected Section\n" +
		"- StartsAt: \n" +
		"\n"
	if !strings.HasPrefix(runner.captured, wantPrefix) {
		t.Errorf("user prompt header mismatch.\nwant prefix:\n%q\ngot:\n%q", wantPrefix, runner.captured)
	}
}

// TestProcessAlert_TitleFormatting verifies that the published title includes
// the namespace when present and omits it when absent.
func TestProcessAlert_TitleFormatting(t *testing.T) {
	cases := []struct {
		name      string
		namespace string
		wantTitle string
	}{
		{"with namespace", "monitoring", "Analysis: HighMemory (monitoring)"},
		{"no namespace", "", "Analysis: HighMemory"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			pub := &mockPublisher{}
			metrics := shared.NewAlertMetrics(shared.NewPrometheusMetricsForTest(shared.ProductK8s))

			deps := PipelineDeps{
				ToolRunner: &fakeToolLoopRunner{
					driver: func(_ func(string, json.RawMessage) (string, error)) (string, error) {
						return "analysis", nil
					},
				},
				KubectlRunner: &fakeKubectlRunner{},
				Prom:          &fakePromQLQuerier{},
				Publishers:    []shared.Publisher{pub},
				Cooldown:      shared.NewCooldownManager(),
				Metrics:       metrics,
				Policy:        &shared.AnalysisPolicy{DefaultModel: "test-model", DefaultMaxRounds: 10},
				GatherContext: func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext {
					return shared.AnalysisContext{}
				},
			}

			fields := map[string]string{"label:namespace": tc.namespace}
			alert := shared.AlertPayload{
				Fingerprint: "fp-title",
				Title:       "HighMemory",
				Severity:    "warning",
				Fields:      fields,
			}
			ProcessAlert(context.Background(), deps, alert)

			if len(pub.calls) != 1 {
				t.Fatalf("expected 1 publish call, got %d", len(pub.calls))
			}
			if pub.calls[0].title != tc.wantTitle {
				t.Errorf("title = %q, want %q", pub.calls[0].title, tc.wantTitle)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Phase 2: phase-differentiated cleanup + Permit + breaker behavior tests
// ---------------------------------------------------------------------------

// TestProcessAlert_PreAPIFailureClearsCooldowns verifies that a panic before
// the breaker permit is acquired (Pre-API phase, e.g. inside GatherContext)
// clears both fingerprint and group cooldowns so the next webhook can retry.
func TestProcessAlert_PreAPIFailureClearsCooldowns(t *testing.T) {
	cm := shared.NewCooldownManager()
	cm.CheckAndSet("fp1", time.Hour)
	cm.CheckAndSetGroup("g1", time.Hour)

	deps := PipelineDeps{
		Cooldown: cm,
		Metrics:  &shared.AlertMetrics{},
		Policy:   &shared.AnalysisPolicy{DefaultModel: "x", DefaultMaxRounds: 0},
		GatherContext: func(ctx context.Context, a shared.AlertPayload) shared.AnalysisContext {
			panic("simulated gather failure")
		},
		Analyzer:   &mockAnalyzer{},
		ToolRunner: &mockToolRunner{},
		Publishers: []shared.Publisher{&pipelineFakePublisher{}},
	}
	alert := shared.AlertPayload{Fingerprint: "fp1", GroupKey: "g1"}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic re-raise")
		}
		// After panic recovery, cooldowns should be cleared
		if !cm.CheckAndSet("fp1", time.Second) {
			t.Fatal("PreAPI panic: fp1 should be clear")
		}
		if !cm.CheckAndSetGroup("g1", time.Second) {
			t.Fatal("PreAPI panic: g1 should be clear")
		}
	}()
	ProcessAlert(context.Background(), deps, alert)
}

// TestProcessAlert_APIFailureClearsCooldowns verifies that a non-circuit-open
// error from the analyzer (API phase) clears cooldowns so the next webhook can
// trigger a retry of the cheap static-only analysis.
func TestProcessAlert_APIFailureClearsCooldowns(t *testing.T) {
	cm := shared.NewCooldownManager()
	cm.CheckAndSet("fp1", time.Hour)
	cm.CheckAndSetGroup("g1", time.Hour)

	deps := PipelineDeps{
		Cooldown:      cm,
		Metrics:       &shared.AlertMetrics{},
		Policy:        &shared.AnalysisPolicy{DefaultModel: "x", DefaultMaxRounds: 0},
		GatherContext: func(_ context.Context, _ shared.AlertPayload) shared.AnalysisContext { return shared.AnalysisContext{} },
		Analyzer:      &mockAnalyzer{returnErr: errors.New("api 503")},
		ToolRunner:    &mockToolRunner{},
		Publishers:    []shared.Publisher{&pipelineFakePublisher{}},
	}
	alert := shared.AlertPayload{Fingerprint: "fp1", GroupKey: "g1"}

	ProcessAlert(context.Background(), deps, alert)

	if !cm.CheckAndSet("fp1", time.Second) {
		t.Fatal("API err: fp1 should be cleared")
	}
	if !cm.CheckAndSetGroup("g1", time.Second) {
		t.Fatal("API err: g1 should be cleared")
	}
}

// TestProcessAlert_ErrCircuitOpenKeepsCooldowns verifies the
// Verstärker-Mitigation: when the breaker is open and Acquire returns
// ErrCircuitOpen, both cooldowns must remain set so Alertmanager retries are
// absorbed at the cooldown layer instead of hammering the closed breaker.
func TestProcessAlert_ErrCircuitOpenKeepsCooldowns(t *testing.T) {
	cm := shared.NewCooldownManager()
	cm.CheckAndSet("fp1", time.Hour)
	cm.CheckAndSetGroup("g1", time.Hour)
	clk := &pipelineFakeClock{t: time.Unix(0, 0)}
	breaker := shared.NewCircuitBreaker(1, time.Hour, time.Hour, clk.Now)
	p, _ := breaker.Acquire()
	p.Done(errors.New("seed"))

	deps := PipelineDeps{
		Cooldown:      cm,
		Breaker:       breaker,
		Metrics:       &shared.AlertMetrics{},
		Policy:        &shared.AnalysisPolicy{DefaultModel: "x", DefaultMaxRounds: 0},
		GatherContext: func(_ context.Context, _ shared.AlertPayload) shared.AnalysisContext { return shared.AnalysisContext{} },
		Analyzer:      &mockAnalyzer{},
		ToolRunner:    &mockToolRunner{},
		Publishers:    []shared.Publisher{&pipelineFakePublisher{}},
	}
	alert := shared.AlertPayload{Fingerprint: "fp1", GroupKey: "g1"}

	ProcessAlert(context.Background(), deps, alert)

	if cm.CheckAndSet("fp1", time.Second) {
		t.Fatal("ErrCircuitOpen: fp1 should NOT be cleared")
	}
	if cm.CheckAndSetGroup("g1", time.Second) {
		t.Fatal("ErrCircuitOpen: g1 should NOT be cleared")
	}
}

// TestProcessAlert_PostAPIFailureKeepsCooldowns verifies that when the
// analysis succeeded but the ntfy publish failed (Post-API phase), neither
// cooldown is cleared — re-running an expensive analysis just because ntfy
// is unavailable wastes API spend.
func TestProcessAlert_PostAPIFailureKeepsCooldowns(t *testing.T) {
	cm := shared.NewCooldownManager()
	cm.CheckAndSet("fp1", time.Hour)
	cm.CheckAndSetGroup("g1", time.Hour)

	failingPub := &pipelineFakePublisher{failNext: errors.New("ntfy down")}
	deps := PipelineDeps{
		Cooldown:      cm,
		Metrics:       &shared.AlertMetrics{},
		Policy:        &shared.AnalysisPolicy{DefaultModel: "x", DefaultMaxRounds: 0},
		GatherContext: func(_ context.Context, _ shared.AlertPayload) shared.AnalysisContext { return shared.AnalysisContext{} },
		Analyzer:      &mockAnalyzer{returnAnalysis: "ok"},
		ToolRunner:    &mockToolRunner{},
		Publishers:    []shared.Publisher{failingPub},
	}
	alert := shared.AlertPayload{Fingerprint: "fp1", GroupKey: "g1"}

	ProcessAlert(context.Background(), deps, alert)

	if cm.CheckAndSet("fp1", time.Second) {
		t.Fatal("PostAPI err: fp1 should NOT be cleared")
	}
	if cm.CheckAndSetGroup("g1", time.Second) {
		t.Fatal("PostAPI err: g1 should NOT be cleared")
	}
}

// TestProcessAlert_HalfOpenProbeForcesRoundsZero verifies that when the
// breaker hands out a half-open probe permit, the pipeline forces rounds=0
// (static-only Analyze) regardless of the policy's configured budget. This
// keeps the probe cheap and bounded.
func TestProcessAlert_HalfOpenProbeForcesRoundsZero(t *testing.T) {
	cm := shared.NewCooldownManager()
	clk := &pipelineFakeClock{t: time.Unix(0, 0)}
	breaker := shared.NewCircuitBreaker(1, 10*time.Second, time.Minute, clk.Now)
	p, _ := breaker.Acquire()
	p.Done(errors.New("seed"))
	clk.advance(11 * time.Second)

	an := &mockAnalyzer{returnAnalysis: "ok"}
	tr := &mockToolRunner{}
	deps := PipelineDeps{
		Cooldown:      cm,
		Breaker:       breaker,
		Metrics:       &shared.AlertMetrics{},
		Policy:        &shared.AnalysisPolicy{DefaultModel: "x", DefaultMaxRounds: 10},
		GatherContext: func(_ context.Context, _ shared.AlertPayload) shared.AnalysisContext { return shared.AnalysisContext{} },
		Analyzer:      an,
		ToolRunner:    tr,
		Publishers:    []shared.Publisher{&pipelineFakePublisher{}},
	}
	alert := shared.AlertPayload{Fingerprint: "fp1", SeverityLevel: shared.SeverityCritical}

	ProcessAlert(context.Background(), deps, alert)

	if an.calls != 1 || tr.calls != 0 {
		t.Fatalf("half-open probe: Analyzer.calls=%d ToolRunner.calls=%d, want 1/0", an.calls, tr.calls)
	}
}

// TestProcessAlert_StormDegradedForcesRoundsZero verifies that when storm-mode
// is degraded, the pipeline forces rounds=0 regardless of policy.MaxRoundsFor,
// shedding tool-loop cost during the burst.
func TestProcessAlert_StormDegradedForcesRoundsZero(t *testing.T) {
	cm := shared.NewCooldownManager()
	storm := shared.NewStormDetector(1, time.Now)
	storm.Record()
	storm.Record() // count=2 > threshold=1

	an := &mockAnalyzer{returnAnalysis: "ok"}
	tr := &mockToolRunner{}
	deps := PipelineDeps{
		Cooldown:      cm,
		Metrics:       &shared.AlertMetrics{},
		Policy:        &shared.AnalysisPolicy{DefaultModel: "x", DefaultMaxRounds: 10, Storm: storm},
		GatherContext: func(_ context.Context, _ shared.AlertPayload) shared.AnalysisContext { return shared.AnalysisContext{} },
		Analyzer:      an,
		ToolRunner:    tr,
		Publishers:    []shared.Publisher{&pipelineFakePublisher{}},
	}
	alert := shared.AlertPayload{Fingerprint: "fp1", SeverityLevel: shared.SeverityCritical}

	ProcessAlert(context.Background(), deps, alert)

	if an.calls != 1 || tr.calls != 0 {
		t.Fatalf("storm-degraded: Analyzer.calls=%d ToolRunner.calls=%d, want 1/0", an.calls, tr.calls)
	}
}

// TestProcessAlert_StormModeAggregatesNotification verifies that when storm-mode
// is degraded AND deps.StormNotify is configured, a successful analysis is handed
// off to the aggregator instead of being published directly to deps.Publishers.
// This covers the `deps.StormNotify.Add(alertname)` branch in pipeline.go.
func TestProcessAlert_StormModeAggregatesNotification(t *testing.T) {
	cm := shared.NewCooldownManager()
	storm := shared.NewStormDetector(1, time.Now)
	storm.Record()
	storm.Record() // count=2 > threshold=1 → IsDegraded() == true

	an := &mockAnalyzer{returnAnalysis: "analysis text"}

	directPub := &pipelineFakePublisher{}
	stormPub := &pipelineFakePublisher{}
	stormNotify := shared.NewNotifyAggregator([]shared.Publisher{stormPub}, time.Hour, "Storm: %d alerts", "3", nil)
	defer stormNotify.Stop(context.Background())

	deps := PipelineDeps{
		Cooldown:      cm,
		Metrics:       &shared.AlertMetrics{},
		Policy:        &shared.AnalysisPolicy{DefaultModel: "x", DefaultMaxRounds: 0, Storm: storm},
		GatherContext: func(_ context.Context, _ shared.AlertPayload) shared.AnalysisContext { return shared.AnalysisContext{} },
		Analyzer:      an,
		ToolRunner:    &mockToolRunner{},
		Publishers:    []shared.Publisher{directPub},
		StormNotify:   stormNotify,
	}
	alert := shared.AlertPayload{Fingerprint: "fp1", Title: "TargetDown", SeverityLevel: shared.SeverityWarning}

	ProcessAlert(context.Background(), deps, alert)

	// Analysis must have run (rounds=0 forced by storm, but Analyzer is called).
	if an.calls != 1 {
		t.Fatalf("expected Analyzer to be called once; got %d", an.calls)
	}

	// The direct publisher must NOT have been called — storm mode aggregates.
	if n := len(directPub.calls); n != 0 {
		t.Fatalf("direct publisher should not be called in storm mode; got %d calls", n)
	}

	// Flush the aggregator and confirm the stormPub received the batched notification.
	if err := stormNotify.Stop(context.Background()); err != nil {
		t.Fatalf("StormNotify.Stop: %v", err)
	}
	if n := len(stormPub.calls); n != 1 {
		t.Fatalf("storm aggregator publisher should receive exactly 1 flush; got %d calls", n)
	}
}

// TestProcessAlert_AnalyzerPanicOpensBreaker verifies that a PANIC during
// analysis is reported as a failure through the permit so the breaker can
// open. Without the cleanup-defer ordering fix (permit.Done after recover()),
// the closure-form `defer func() { permit.Done(analysisErr) }()` would run
// FIRST in the LIFO defer chain — observing analysisErr=nil because the
// assignment never completed — and the breaker would record a SUCCESS for
// the panicked analysis. Final-review regression test.
func TestProcessAlert_AnalyzerPanicOpensBreaker(t *testing.T) {
	cm := shared.NewCooldownManager()
	clk := &pipelineFakeClock{t: time.Unix(0, 0)}
	breaker := shared.NewCircuitBreaker(1, time.Hour, time.Hour, clk.Now)

	// Mock that panics inside Analyze. Use the existing mockAnalyzer struct
	// from the file's fixtures by wrapping its Analyze with a panic.
	panicAnalyzer := &panicMockAnalyzer{msg: "boom"}

	deps := PipelineDeps{
		Cooldown:      cm,
		Breaker:       breaker,
		Metrics:       &shared.AlertMetrics{},
		Policy:        &shared.AnalysisPolicy{DefaultModel: "x", DefaultMaxRounds: 0},
		GatherContext: func(_ context.Context, _ shared.AlertPayload) shared.AnalysisContext { return shared.AnalysisContext{} },
		Analyzer:      panicAnalyzer,
		ToolRunner:    &mockToolRunner{},
		Publishers:    []shared.Publisher{&pipelineFakePublisher{}},
	}

	// One panicked analysis with threshold=1 should open the breaker.
	func() {
		defer func() { _ = recover() }() // swallow the re-panic so the test continues
		ProcessAlert(context.Background(), deps, shared.AlertPayload{Fingerprint: "fp1"})
	}()

	if _, err := breaker.Acquire(); !errors.Is(err, shared.ErrCircuitOpen) {
		t.Fatalf("breaker should be open after a panicked analysis; Acquire returned err=%v", err)
	}
}

// panicMockAnalyzer panics in Analyze(); used by TestProcessAlert_AnalyzerPanicOpensBreaker.
type panicMockAnalyzer struct {
	msg string
}

func (p *panicMockAnalyzer) Analyze(_ context.Context, _ shared.Severity, _, _, _ string) (string, error) {
	panic(p.msg)
}

// TestProcessAlert_AnalyzerErrorOpensBreaker verifies that an analysis failure
// is correctly reported through the permit so that the breaker's
// consecFailures counter increments and the breaker eventually opens.
//
// Regression test for the lazy-eval bug in `defer permit.Done(analysisErr)`:
// if the deferred call evaluates analysisErr at defer-registration time
// (when it is nil because we just passed the err==nil check after Acquire),
// the breaker sees Done(nil) — success — and never opens regardless of how
// many analyses fail. The fix is `defer func() { permit.Done(analysisErr) }()`
// so the closure reads analysisErr at execution time.
func TestProcessAlert_AnalyzerErrorOpensBreaker(t *testing.T) {
	cm := shared.NewCooldownManager()
	clk := &pipelineFakeClock{t: time.Unix(0, 0)}
	breaker := shared.NewCircuitBreaker(2, time.Hour, time.Hour, clk.Now)

	deps := PipelineDeps{
		Cooldown:      cm,
		Breaker:       breaker,
		Metrics:       &shared.AlertMetrics{},
		Policy:        &shared.AnalysisPolicy{DefaultModel: "x", DefaultMaxRounds: 0},
		GatherContext: func(_ context.Context, _ shared.AlertPayload) shared.AnalysisContext { return shared.AnalysisContext{} },
		Analyzer:      &mockAnalyzer{returnErr: errors.New("api 503")},
		ToolRunner:    &mockToolRunner{},
		Publishers:    []shared.Publisher{&pipelineFakePublisher{}},
	}

	// Two failed analyses must hit the threshold and open the breaker.
	for i := 0; i < 2; i++ {
		alert := shared.AlertPayload{Fingerprint: fmt.Sprintf("fp%d", i)}
		ProcessAlert(context.Background(), deps, alert)
	}

	// Third Acquire should now return ErrCircuitOpen.
	if _, err := breaker.Acquire(); !errors.Is(err, shared.ErrCircuitOpen) {
		t.Fatalf("breaker should be open after 2 failed analyses; Acquire returned err=%v", err)
	}
}

// TestProcessAlert_ToolLoopPanicOpensBreaker verifies that a panic in the
// agentic (rounds > 0) path is correctly reported through the permit so the
// circuit breaker opens. This is the agentic-path counterpart to
// TestProcessAlert_AnalyzerPanicOpensBreaker (which covers rounds==0).
//
// The cleanup-defer ordering — recover() runs first, sets analysisErr, then
// permit.Done(analysisErr) — must hold for both the static and agentic paths.
// Without it, permit.Done would observe analysisErr==nil and record a success
// for the panicked tool-loop round, leaving the breaker closed.
func TestProcessAlert_ToolLoopPanicOpensBreaker(t *testing.T) {
	cm := shared.NewCooldownManager()
	clk := &pipelineFakeClock{t: time.Unix(0, 0)}
	breaker := shared.NewCircuitBreaker(1, time.Hour, time.Hour, clk.Now)

	deps := PipelineDeps{
		Cooldown: cm,
		Breaker:  breaker,
		Metrics:  &shared.AlertMetrics{},
		Policy:   &shared.AnalysisPolicy{DefaultModel: "x", DefaultMaxRounds: 1},
		GatherContext: func(_ context.Context, _ shared.AlertPayload) shared.AnalysisContext {
			return shared.AnalysisContext{}
		},
		Analyzer: &mockAnalyzer{returnAnalysis: "ok"},
		ToolRunner: &fakeToolLoopRunner{
			driver: func(_ func(string, json.RawMessage) (string, error)) (string, error) {
				panic("simulated tool-loop panic")
			},
		},
		KubectlRunner: &fakeKubectlRunner{},
		Prom:          &fakePromQLQuerier{},
		Publishers:    []shared.Publisher{&pipelineFakePublisher{}},
	}

	// One panicked agentic analysis with threshold=1 should open the breaker.
	func() {
		defer func() { _ = recover() }() // swallow the re-panic so the test continues
		ProcessAlert(context.Background(), deps, shared.AlertPayload{Fingerprint: "fp1"})
	}()

	if _, err := breaker.Acquire(); !errors.Is(err, shared.ErrCircuitOpen) {
		t.Fatalf("breaker should be open after agentic-path tool-loop panic; Acquire returned err=%v", err)
	}
}

// ---------------------------------------------------------------------------
// Test fixtures for Phase 2 pipeline tests.
// Names are prefixed/suffixed to avoid collision with Phase 1 helpers above.
// ---------------------------------------------------------------------------

type mockAnalyzer struct {
	calls          int
	returnAnalysis string
	returnErr      error
}

func (m *mockAnalyzer) Analyze(ctx context.Context, _ shared.Severity, model, system, user string) (string, error) {
	m.calls++
	if m.returnErr != nil {
		return "", m.returnErr
	}
	return m.returnAnalysis, nil
}

type mockToolRunner struct {
	calls int
}

func (m *mockToolRunner) RunToolLoop(
	ctx context.Context, _ shared.Severity, model, system, user string,
	tools []anthropic.ToolUnionParam, maxRounds int,
	handleTool func(name string, input json.RawMessage) (string, error),
) (string, int, bool, error) {
	m.calls++
	return "ok", 1, false, nil
}

type pipelineFakePublisher struct {
	mu       sync.Mutex
	calls    []pipelineFakePublishCall
	failNext error
}
type pipelineFakePublishCall struct{ title, priority, body string }

func (p *pipelineFakePublisher) Name() string { return "fake" }
func (p *pipelineFakePublisher) Publish(ctx context.Context, title, priority, body string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failNext != nil {
		err := p.failNext
		p.failNext = nil
		return err
	}
	p.calls = append(p.calls, pipelineFakePublishCall{title, priority, body})
	return nil
}

type pipelineFakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *pipelineFakeClock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *pipelineFakeClock) advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// TestVerstaerkerBug_OpenBreakerKeepsCooldown_NoSecondAnalysis is the most
// important behavioral test of the storm/cost-protection spec: an open
// circuit-breaker plus a re-fired Alertmanager webhook must NOT result in a
// second analysis attempt. The cooldown layer absorbs Alertmanager retries
// so the closed breaker is not hammered.
func TestVerstaerkerBug_OpenBreakerKeepsCooldown_NoSecondAnalysis(t *testing.T) {
	// 1. Setup: cooldown manager + breaker with threshold=1 (already failed once below).
	cm := shared.NewCooldownManager()
	clk := &pipelineFakeClock{t: time.Unix(0, 0)}
	breaker := shared.NewCircuitBreaker(1, time.Hour, time.Hour, clk.Now)
	// Pre-fail the breaker so it's open.
	p, _ := breaker.Acquire()
	p.Done(errors.New("seed failure"))

	an := &mockAnalyzer{returnAnalysis: "ok"}
	tr := &mockToolRunner{}

	pub := &pipelineFakePublisher{}
	breakerNotify := shared.NewNotifyAggregator([]shared.Publisher{pub}, time.Hour, "Aggregate: %d", "5", nil)
	defer breakerNotify.Stop(context.Background())

	deps := PipelineDeps{
		Cooldown:      cm,
		Breaker:       breaker,
		BreakerNotify: breakerNotify,
		Metrics:       &shared.AlertMetrics{},
		Policy:        &shared.AnalysisPolicy{DefaultModel: "x", DefaultMaxRounds: 0},
		GatherContext: func(_ context.Context, _ shared.AlertPayload) shared.AnalysisContext { return shared.AnalysisContext{} },
		Analyzer:      an,
		ToolRunner:    tr,
		Publishers:    []shared.Publisher{pub},
	}

	// 2. Set the cooldown as if a previous webhook had set it.
	cm.CheckAndSet("fp1", time.Hour)
	cm.CheckAndSetGroup("g1", time.Hour)

	// 3. ProcessAlert with breaker open → ErrCircuitOpen → cooldowns must remain.
	alert := shared.AlertPayload{Fingerprint: "fp1", GroupKey: "g1", SeverityLevel: shared.SeverityWarning}
	ProcessAlert(context.Background(), deps, alert)

	if cm.CheckAndSet("fp1", time.Second) {
		t.Fatal("after ErrCircuitOpen: fp1 cooldown should still be set")
	}
	if cm.CheckAndSetGroup("g1", time.Second) {
		t.Fatal("after ErrCircuitOpen: g1 cooldown should still be set")
	}
	if an.calls != 0 || tr.calls != 0 {
		t.Fatalf("Claude must NOT have been called; analyzer=%d tool=%d", an.calls, tr.calls)
	}

	// 4. Simulate Alertmanager retry at the pipeline level — same alert, breaker still open.
	ProcessAlert(context.Background(), deps, alert)
	if an.calls != 0 || tr.calls != 0 {
		t.Fatalf("retry: Claude must STILL not have been called; analyzer=%d tool=%d", an.calls, tr.calls)
	}
}

// fakeHistoryStore implements shared.HistoryStore for pipeline tests. It
// returns a pre-configured HistoryView on every Lookup, letting tests verify
// the InjectHistory integration path without a real SQLite database.
type fakeHistoryStore struct {
	view     shared.HistoryView
	analyses int
	lastSev  shared.Severity
	lastSum  string
}

func (f *fakeHistoryStore) RecordFire(_ context.Context, _ string, _ shared.Severity) {}
func (f *fakeHistoryStore) RecordAnalysis(_ context.Context, _ string, sev shared.Severity, sum string) {
	f.analyses++
	f.lastSev = sev
	f.lastSum = sum
}
func (f *fakeHistoryStore) Lookup(_ context.Context, _ string) shared.HistoryView { return f.view }
func (f *fakeHistoryStore) Close() error                                          { return nil }

// TestProcessAlert_InjectsRecurrenceHistoryIntoPrompt verifies that when the
// HistoryStore reports count > 1 for an alert fingerprint, InjectHistory
// prepends the "Alert Recurrence" section to the user prompt sent to Claude.
// This is the pipeline-level integration test for the history recurrence feature:
// the unit tests in history_test.go cover InjectHistory in isolation, but this
// test confirms the wiring inside ProcessAlert passes the section through to
// the actual Claude invocation.
func TestProcessAlert_InjectsRecurrenceHistoryIntoPrompt(t *testing.T) {
	runner := &fakeToolLoopRunner{
		driver: func(_ func(string, json.RawMessage) (string, error)) (string, error) {
			return "analysis", nil
		},
	}
	history := &fakeHistoryStore{
		view: shared.HistoryView{Count: 3, Window: 6 * time.Hour},
	}
	deps := PipelineDeps{
		ToolRunner:         runner,
		KubectlRunner:      &fakeKubectlRunner{},
		Prom:               &fakePromQLQuerier{},
		Publishers:         []shared.Publisher{&mockPublisher{}},
		Cooldown:           shared.NewCooldownManager(),
		Metrics:            shared.NewAlertMetrics(shared.NewPrometheusMetricsForTest(shared.ProductK8s)),
		Policy:             &shared.AnalysisPolicy{DefaultModel: "test-model", DefaultMaxRounds: 1},
		GatherContext:      func(context.Context, shared.AlertPayload) shared.AnalysisContext { return shared.AnalysisContext{} },
		History:            history,
		HistoryInjectPrior: false,
	}

	ProcessAlert(context.Background(), deps, shared.AlertPayload{
		Fingerprint: "fp-recurring",
		Title:       "HighCPU",
		Severity:    "warning",
		Fields:      map[string]string{},
	})

	if !strings.Contains(runner.captured, "Alert Recurrence") {
		t.Errorf("recurrence section not injected into prompt; got:\n%s", runner.captured)
	}
	if !strings.Contains(runner.captured, "fired 3 times") {
		t.Errorf("fire count not in prompt; got:\n%s", runner.captured)
	}
	if !strings.Contains(runner.captured, "6h") {
		t.Errorf("window not in prompt; got:\n%s", runner.captured)
	}
}

// TestProcessAlert_RecordsAnalysisAfterSuccess verifies that ProcessAlert calls
// RecordAnalysis on the history store after a successful analysis and publish.
func TestProcessAlert_RecordsAnalysisAfterSuccess(t *testing.T) {
	const wantSummary = "analysis result"
	runner := &fakeToolLoopRunner{
		driver: func(_ func(string, json.RawMessage) (string, error)) (string, error) {
			return wantSummary, nil
		},
	}
	history := &fakeHistoryStore{}
	deps := PipelineDeps{
		ToolRunner:    runner,
		KubectlRunner: &fakeKubectlRunner{},
		Prom:          &fakePromQLQuerier{},
		Publishers:    []shared.Publisher{&mockPublisher{}},
		Cooldown:      shared.NewCooldownManager(),
		Metrics:       shared.NewAlertMetrics(shared.NewPrometheusMetricsForTest(shared.ProductK8s)),
		Policy:        &shared.AnalysisPolicy{DefaultModel: "test-model", DefaultMaxRounds: 1},
		GatherContext: func(context.Context, shared.AlertPayload) shared.AnalysisContext { return shared.AnalysisContext{} },
		History:       history,
	}

	ProcessAlert(context.Background(), deps, shared.AlertPayload{
		Fingerprint:   "fp-record",
		Title:         "HighCPU",
		Severity:      "warning",
		SeverityLevel: shared.SeverityWarning,
		Fields:        map[string]string{},
	})

	if history.analyses != 1 {
		t.Errorf("RecordAnalysis called %d times, want 1", history.analyses)
	}
	if history.lastSev != shared.SeverityWarning {
		t.Errorf("RecordAnalysis severity = %v, want warning", history.lastSev)
	}
	if history.lastSum != wantSummary {
		t.Errorf("RecordAnalysis summary = %q, want %q", history.lastSum, wantSummary)
	}
}

// TestProcessAlert_RecordsAndStripsSummary verifies that when the analysis ends
// with a SUMMARY: line, the stored history summary is the SUMMARY text (not the
// whole analysis) and the published body has the SUMMARY: line stripped while
// retaining the analysis content.
func TestProcessAlert_RecordsAndStripsSummary(t *testing.T) {
	const summaryText = "node ran out of memory"
	const analysis = "## Root cause\nThe pod was OOM-killed.\nSUMMARY: " + summaryText
	pub := &mockPublisher{}
	history := &fakeHistoryStore{}
	deps := PipelineDeps{
		ToolRunner: &fakeToolLoopRunner{
			driver: func(_ func(string, json.RawMessage) (string, error)) (string, error) {
				return analysis, nil
			},
		},
		KubectlRunner: &fakeKubectlRunner{},
		Prom:          &fakePromQLQuerier{},
		Publishers:    []shared.Publisher{pub},
		Cooldown:      shared.NewCooldownManager(),
		Metrics:       shared.NewAlertMetrics(shared.NewPrometheusMetricsForTest(shared.ProductK8s)),
		Policy:        &shared.AnalysisPolicy{DefaultModel: "test-model", DefaultMaxRounds: 1},
		GatherContext: func(context.Context, shared.AlertPayload) shared.AnalysisContext { return shared.AnalysisContext{} },
		History:       history,
	}

	ProcessAlert(context.Background(), deps, shared.AlertPayload{
		Fingerprint:   "fp-strip",
		Title:         "HighMemory",
		Severity:      "warning",
		SeverityLevel: shared.SeverityWarning,
		Fields:        map[string]string{},
	})

	if history.analyses != 1 {
		t.Fatalf("RecordAnalysis called %d times, want 1", history.analyses)
	}
	if history.lastSum != summaryText {
		t.Errorf("stored summary = %q, want %q", history.lastSum, summaryText)
	}
	bodies := pub.published()
	if len(bodies) != 1 {
		t.Fatalf("published %d bodies, want 1", len(bodies))
	}
	if strings.Contains(bodies[0], "SUMMARY:") {
		t.Errorf("published body still contains SUMMARY: line: %q", bodies[0])
	}
	if !strings.Contains(bodies[0], "The pod was OOM-killed.") {
		t.Errorf("published body missing analysis content: %q", bodies[0])
	}
}

// TestProcessAlert_EmptySummaryNotRecorded verifies that when ParseSummary
// yields an empty summary (e.g. a headings-only analysis with no usable line),
// no prior-analysis row is recorded and the body is published unchanged.
func TestProcessAlert_EmptySummaryNotRecorded(t *testing.T) {
	const analysis = "## Root cause\n## Only headings here"
	pub := &mockPublisher{}
	history := &fakeHistoryStore{}
	deps := PipelineDeps{
		ToolRunner: &fakeToolLoopRunner{
			driver: func(_ func(string, json.RawMessage) (string, error)) (string, error) {
				return analysis, nil
			},
		},
		KubectlRunner: &fakeKubectlRunner{},
		Prom:          &fakePromQLQuerier{},
		Publishers:    []shared.Publisher{pub},
		Cooldown:      shared.NewCooldownManager(),
		Metrics:       shared.NewAlertMetrics(shared.NewPrometheusMetricsForTest(shared.ProductK8s)),
		Policy:        &shared.AnalysisPolicy{DefaultModel: "test-model", DefaultMaxRounds: 1},
		GatherContext: func(context.Context, shared.AlertPayload) shared.AnalysisContext { return shared.AnalysisContext{} },
		History:       history,
	}

	ProcessAlert(context.Background(), deps, shared.AlertPayload{
		Fingerprint:   "fp-empty-sum",
		Title:         "HighMemory",
		Severity:      "warning",
		SeverityLevel: shared.SeverityWarning,
		Fields:        map[string]string{},
	})

	if history.analyses != 0 {
		t.Errorf("RecordAnalysis called %d times, want 0 (empty summary)", history.analyses)
	}
	bodies := pub.published()
	if len(bodies) != 1 {
		t.Fatalf("published %d bodies, want 1", len(bodies))
	}
	if bodies[0] != analysis {
		t.Errorf("published body = %q, want unchanged %q", bodies[0], analysis)
	}
}

// TestProcessAlert_RecordsHistoryLookupMetric verifies that RecordHistoryLookup
// is wired correctly inside ProcessAlert for all three Count cases:
//   - Count == 0 (history disabled / nop store): metric must NOT be recorded
//   - Count == 1 (first fire, no prior context): metric recorded as miss
//   - Count > 1 (recurring alert): metric recorded as hit
func TestProcessAlert_RecordsHistoryLookupMetric(t *testing.T) {
	for _, tc := range []struct {
		name     string
		count    int
		wantHit  float64
		wantMiss float64
	}{
		{"count=0 (disabled)", 0, 0, 0},
		{"count=1 (miss)", 1, 0, 1},
		{"count=3 (hit)", 3, 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prom := shared.NewPrometheusMetricsForTest(shared.ProductK8s)
			metrics := shared.NewAlertMetrics(prom)
			history := &fakeHistoryStore{
				view: shared.HistoryView{Count: tc.count},
			}
			deps := PipelineDeps{
				ToolRunner:    &fakeToolLoopRunner{driver: func(_ func(string, json.RawMessage) (string, error)) (string, error) { return "ok", nil }},
				KubectlRunner: &fakeKubectlRunner{},
				Prom:          &fakePromQLQuerier{},
				Publishers:    []shared.Publisher{&mockPublisher{}},
				Cooldown:      shared.NewCooldownManager(),
				Metrics:       metrics,
				Policy:        &shared.AnalysisPolicy{DefaultModel: "test-model", DefaultMaxRounds: 1},
				GatherContext: func(context.Context, shared.AlertPayload) shared.AnalysisContext { return shared.AnalysisContext{} },
				History:       history,
			}

			ProcessAlert(context.Background(), deps, shared.AlertPayload{
				Fingerprint: "fp-lookup-metric",
				Fields:      map[string]string{},
			})

			if got := testutil.ToFloat64(prom.HistoryLookups.WithLabelValues("hit")); got != tc.wantHit {
				t.Errorf("HistoryLookups[hit] = %v, want %v", got, tc.wantHit)
			}
			if got := testutil.ToFloat64(prom.HistoryLookups.WithLabelValues("miss")); got != tc.wantMiss {
				t.Errorf("HistoryLookups[miss] = %v, want %v", got, tc.wantMiss)
			}
		})
	}
}

// TestProcessAlert_ObservesRecurrenceCount verifies that ObserveRecurrence is
// called with the correct count from ProcessAlert. count=0 and count=1 must
// not record a histogram observation; count>1 must record exactly one
// observation whose sum equals the count.
func TestProcessAlert_ObservesRecurrenceCount(t *testing.T) {
	for _, tc := range []struct {
		name       string
		count      int
		wantSample uint64
		wantSum    float64
	}{
		{"count=0 (no lookup)", 0, 0, 0},
		{"count=1 (first fire)", 1, 0, 0},
		{"count=3 (recurrence)", 3, 1, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prom := shared.NewPrometheusMetricsForTest(shared.ProductK8s)
			metrics := shared.NewAlertMetrics(prom)
			history := &fakeHistoryStore{
				view: shared.HistoryView{Count: tc.count},
			}
			deps := PipelineDeps{
				ToolRunner:    &fakeToolLoopRunner{driver: func(_ func(string, json.RawMessage) (string, error)) (string, error) { return "ok", nil }},
				KubectlRunner: &fakeKubectlRunner{},
				Prom:          &fakePromQLQuerier{},
				Publishers:    []shared.Publisher{&mockPublisher{}},
				Cooldown:      shared.NewCooldownManager(),
				Metrics:       metrics,
				Policy:        &shared.AnalysisPolicy{DefaultModel: "test-model", DefaultMaxRounds: 1},
				GatherContext: func(context.Context, shared.AlertPayload) shared.AnalysisContext { return shared.AnalysisContext{} },
				History:       history,
			}

			ProcessAlert(context.Background(), deps, shared.AlertPayload{
				Fingerprint: "fp-recurrence",
				Fields:      map[string]string{},
			})

			var m dto.Metric
			if err := prom.HistoryRecurrence.Write(&m); err != nil {
				t.Fatalf("HistoryRecurrence.Write: %v", err)
			}
			if got := m.Histogram.GetSampleCount(); got != tc.wantSample {
				t.Errorf("HistoryRecurrence sample count = %d, want %d", got, tc.wantSample)
			}
			if got := m.Histogram.GetSampleSum(); got != tc.wantSum {
				t.Errorf("HistoryRecurrence sample sum = %v, want %v", got, tc.wantSum)
			}
		})
	}
}
