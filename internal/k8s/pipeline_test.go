package k8s

import (
	"context"
	"testing"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
)

type mockAnalyzer struct {
	result string
	err    error
}

func (m *mockAnalyzer) Analyze(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	return m.result, m.err
}

type mockPublisher struct {
	published []string
	err       error
}

func (m *mockPublisher) Publish(ctx context.Context, title, priority, body string) error {
	m.published = append(m.published, body)
	return m.err
}

func (m *mockPublisher) Name() string { return "mock" }

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
	if len(pub.published) != 1 {
		t.Fatalf("published %d, want 1", len(pub.published))
	}
	if pub.published[0] != "root cause: OOM" {
		t.Errorf("published body = %q", pub.published[0])
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
