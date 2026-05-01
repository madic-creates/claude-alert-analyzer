package k8s

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

type mockAnalyzer struct {
	result string
	err    error
}

func (m *mockAnalyzer) Analyze(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	return m.result, m.err
}

type panicAnalyzer struct{}

func (p *panicAnalyzer) Analyze(_ context.Context, _, _ string) (string, error) {
	panic("simulated analysis panic")
}

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

func TestProcessAlert_Success(t *testing.T) {
	pub := &mockPublisher{}
	cooldown := shared.NewCooldownManager()
	metrics := new(shared.AlertMetrics)

	deps := PipelineDeps{
		Analyzer:     &mockAnalyzer{result: "root cause: OOM"},
		Publishers:   []shared.Publisher{pub},
		Cooldown:     cooldown,
		Metrics:      metrics,
		SystemPrompt: "test prompt",
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

	if metrics.AlertsProcessed.Load() != 1 {
		t.Errorf("AlertsProcessed = %d, want 1", metrics.AlertsProcessed.Load())
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
	metrics := new(shared.AlertMetrics)

	deps := PipelineDeps{
		Analyzer:     &mockAnalyzer{err: context.DeadlineExceeded},
		Publishers:   []shared.Publisher{pub},
		Cooldown:     cooldown,
		Metrics:      metrics,
		SystemPrompt: "test",
		GatherContext: func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext {
			return shared.AnalysisContext{}
		},
	}

	alert := shared.AlertPayload{Fingerprint: "abc", Title: "Test", Severity: "warning", Fields: map[string]string{}}
	ProcessAlert(context.Background(), deps, alert)

	if metrics.AlertsFailed.Load() != 1 {
		t.Errorf("AlertsFailed = %d, want 1", metrics.AlertsFailed.Load())
	}
	// Cooldown should be cleared on failure
	if !cooldown.CheckAndSet("abc", 300*1e9) {
		t.Error("cooldown not cleared after failure")
	}
}

// TestProcessAlert_PublishFails verifies that when PublishAll returns an error
// the cooldown is cleared (so the alert can be retried) and AlertsFailed is
// incremented.
func TestProcessAlert_PublishFails(t *testing.T) {
	pub := &mockPublisher{err: fmt.Errorf("ntfy unavailable")}
	cooldown := shared.NewCooldownManager()
	metrics := new(shared.AlertMetrics)

	deps := PipelineDeps{
		Analyzer:     &mockAnalyzer{result: "some analysis"},
		Publishers:   []shared.Publisher{pub},
		Cooldown:     cooldown,
		Metrics:      metrics,
		SystemPrompt: "test",
		GatherContext: func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext {
			return shared.AnalysisContext{}
		},
	}

	alert := shared.AlertPayload{Fingerprint: "fp1", Title: "DiskFull", Severity: "critical", Fields: map[string]string{}}
	ProcessAlert(context.Background(), deps, alert)

	if metrics.AlertsFailed.Load() != 1 {
		t.Errorf("AlertsFailed = %d, want 1", metrics.AlertsFailed.Load())
	}
	if metrics.AlertsProcessed.Load() != 0 {
		t.Errorf("AlertsProcessed = %d, want 0", metrics.AlertsProcessed.Load())
	}
	// Cooldown must be cleared so the next webhook can re-trigger analysis.
	if !cooldown.CheckAndSet("fp1", 300*1e9) {
		t.Error("cooldown not cleared after publish failure")
	}
}

// TestProcessAlert_PublishFails_RecordsPrometheusCounter verifies that when
// PublishAll returns an error and Prom is non-nil, the ntfy_publish_errors_total
// Prometheus counter is incremented. The existing TestProcessAlert_PublishFails
// uses new(shared.AlertMetrics) (Prom == nil) so RecordNtfyPublishError is a
// no-op there; this test exercises the non-nil path.
func TestProcessAlert_PublishFails_RecordsPrometheusCounter(t *testing.T) {
	pub := &mockPublisher{err: fmt.Errorf("ntfy unavailable")}
	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetrics()}

	deps := PipelineDeps{
		Analyzer:     &mockAnalyzer{result: "some analysis"},
		Publishers:   []shared.Publisher{pub},
		Cooldown:     shared.NewCooldownManager(),
		Metrics:      metrics,
		SystemPrompt: "test",
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

	got := testutil.ToFloat64(metrics.Prom.NtfyPublishErrors.WithLabelValues("k8s"))
	if got != 1 {
		t.Errorf("ntfy_publish_errors_total{source=\"k8s\"} = %v, want 1", got)
	}
}

// TestProcessAlert_AnalysisFails_RecordsClaudeAPIErrorCounter verifies that
// when Analyze returns an error and Prom is non-nil, the claude_api_errors_total
// Prometheus counter is incremented. The counter is used to alert on sustained
// Claude API outages; without this call the metric is permanently zero.
func TestProcessAlert_AnalysisFails_RecordsClaudeAPIErrorCounter(t *testing.T) {
	pub := &mockPublisher{}
	metrics := &shared.AlertMetrics{Prom: shared.NewPrometheusMetrics()}

	deps := PipelineDeps{
		Analyzer:     &mockAnalyzer{err: context.DeadlineExceeded},
		Publishers:   []shared.Publisher{pub},
		Cooldown:     shared.NewCooldownManager(),
		Metrics:      metrics,
		SystemPrompt: "test",
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

	got := testutil.ToFloat64(metrics.Prom.ClaudeAPIErrors.WithLabelValues("k8s"))
	if got != 1 {
		t.Errorf("claude_api_errors_total{source=\"k8s\"} = %v, want 1", got)
	}
}

// TestProcessAlert_EmptyAnalysis verifies that when Analyze returns ("", nil) —
// which can happen if Claude produces no text content blocks — the pipeline
// treats it as a failure: cooldown is cleared and AlertsFailed is incremented.
func TestProcessAlert_EmptyAnalysis(t *testing.T) {
	pub := &mockPublisher{}
	cooldown := shared.NewCooldownManager()
	metrics := new(shared.AlertMetrics)

	deps := PipelineDeps{
		Analyzer:     &mockAnalyzer{result: "", err: nil},
		Publishers:   []shared.Publisher{pub},
		Cooldown:     cooldown,
		Metrics:      metrics,
		SystemPrompt: "test",
		GatherContext: func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext {
			return shared.AnalysisContext{}
		},
	}

	alert := shared.AlertPayload{Fingerprint: "fp-empty", Title: "EmptyAlert", Severity: "warning", Fields: map[string]string{}}
	ProcessAlert(context.Background(), deps, alert)

	if metrics.AlertsFailed.Load() != 1 {
		t.Errorf("AlertsFailed = %d, want 1", metrics.AlertsFailed.Load())
	}
	if metrics.AlertsProcessed.Load() != 0 {
		t.Errorf("AlertsProcessed = %d, want 0", metrics.AlertsProcessed.Load())
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
	metrics := new(shared.AlertMetrics)

	deps := PipelineDeps{
		Analyzer:     &panicAnalyzer{},
		Publishers:   []shared.Publisher{pub},
		Cooldown:     cooldown,
		Metrics:      metrics,
		SystemPrompt: "test",
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
	if metrics.AlertsFailed.Load() != 1 {
		t.Errorf("AlertsFailed = %d, want 1", metrics.AlertsFailed.Load())
	}
}

// TestProcessAlert_PriorityMapping verifies the severity → ntfy priority table
// and that an unrecognised severity falls back to "3".
func TestProcessAlert_PriorityMapping(t *testing.T) {
	cases := []struct {
		severity string
		want     string
	}{
		{"critical", "5"},
		{"warning", "4"},
		{"info", "2"},
		{"unknown", "3"},  // not in the map → default
		{"", "3"},         // empty → default
		{"CRITICAL", "3"}, // case-sensitive → default
	}

	for _, tc := range cases {
		tc := tc
		t.Run(fmt.Sprintf("severity=%q", tc.severity), func(t *testing.T) {
			pub := &mockPublisher{}
			metrics := new(shared.AlertMetrics)

			deps := PipelineDeps{
				Analyzer:     &mockAnalyzer{result: "analysis"},
				Publishers:   []shared.Publisher{pub},
				Cooldown:     shared.NewCooldownManager(),
				Metrics:      metrics,
				SystemPrompt: "test",
				GatherContext: func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext {
					return shared.AnalysisContext{}
				},
			}

			alert := shared.AlertPayload{
				Fingerprint: "fp-" + tc.severity,
				Title:       "TestAlert",
				Severity:    tc.severity,
				Fields:      map[string]string{},
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
	var capturedPrompt string
	pub := &mockPublisher{}
	metrics := new(shared.AlertMetrics)

	deps := PipelineDeps{
		Analyzer:     &capturePromptAnalyzer{result: "analysis", captured: &capturedPrompt},
		Publishers:   []shared.Publisher{pub},
		Cooldown:     shared.NewCooldownManager(),
		Metrics:      metrics,
		SystemPrompt: "test",
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
	if !strings.HasPrefix(capturedPrompt, wantPrefix) {
		t.Errorf("user prompt header mismatch.\nwant prefix:\n%q\ngot:\n%q", wantPrefix, capturedPrompt)
	}
}

type capturePromptAnalyzer struct {
	result   string
	captured *string
}

func (c *capturePromptAnalyzer) Analyze(_ context.Context, _, userPrompt string) (string, error) {
	*c.captured = userPrompt
	return c.result, nil
}

// TestProcessAlert_FailureBodySanitizesTitle verifies that embedded control
// characters in alert.Title do not appear in the failure notification body.
// A crafted webhook with a title like "Alert\n## Injected" could otherwise
// corrupt the ntfy notification body since NtfyPublisher.Publish does not
// sanitize the body parameter (only the title header).
func TestProcessAlert_FailureBodySanitizesTitle(t *testing.T) {
	pub := &mockPublisher{}
	metrics := new(shared.AlertMetrics)

	deps := PipelineDeps{
		Analyzer:     &mockAnalyzer{err: fmt.Errorf("api error")},
		Publishers:   []shared.Publisher{pub},
		Cooldown:     shared.NewCooldownManager(),
		Metrics:      metrics,
		SystemPrompt: "test",
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

// TestProcessAlert_PromptSanitizesNamespace verifies that embedded control
// characters in the label:namespace field are stripped from the user prompt
// passed to the analyzer. alertname and namespace are sanitized at extraction
// (not inline in the fmt.Sprintf), so this test confirms the invariant holds
// for namespace after the extraction-point sanitization refactor.
func TestProcessAlert_PromptSanitizesNamespace(t *testing.T) {
	var capturedPrompt string
	pub := &mockPublisher{}
	metrics := new(shared.AlertMetrics)

	deps := PipelineDeps{
		Analyzer:     &capturePromptAnalyzer{result: "analysis", captured: &capturedPrompt},
		Publishers:   []shared.Publisher{pub},
		Cooldown:     shared.NewCooldownManager(),
		Metrics:      metrics,
		SystemPrompt: "test",
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
	if !strings.HasPrefix(capturedPrompt, wantPrefix) {
		t.Errorf("user prompt header mismatch.\nwant prefix:\n%q\ngot:\n%q", wantPrefix, capturedPrompt)
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
			metrics := new(shared.AlertMetrics)

			deps := PipelineDeps{
				Analyzer:     &mockAnalyzer{result: "analysis"},
				Publishers:   []shared.Publisher{pub},
				Cooldown:     shared.NewCooldownManager(),
				Metrics:      metrics,
				SystemPrompt: "test",
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
