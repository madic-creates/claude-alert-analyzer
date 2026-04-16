package checkmk

import (
	"context"
	"encoding/json"
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

func (m *mockAnalyzer) RunToolLoop(ctx context.Context, systemPrompt, userPrompt string,
	tools []shared.Tool, maxRounds int, handleTool func(string, json.RawMessage) (string, error)) (string, error) {
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

func TestProcessAlert_NoSSH(t *testing.T) {
	pub := &mockPublisher{}
	cooldown := shared.NewCooldownManager()
	metrics := new(shared.AlertMetrics)

	deps := PipelineDeps{
		Analyzer:   &mockAnalyzer{result: "disk full analysis"},
		Publishers: []shared.Publisher{pub},
		Cooldown:   cooldown,
		Metrics:    metrics,
		SSHEnabled: false,
		GatherContext: func(ctx context.Context, alert shared.AlertPayload, hostInfo *HostInfo) shared.AnalysisContext {
			return shared.AnalysisContext{Sections: []shared.ContextSection{{Name: "Test", Content: "data"}}}
		},
		ValidateHost: func(ctx context.Context, hostname, hostAddress string) (*HostInfo, error) {
			return &HostInfo{}, nil
		},
	}

	alert := shared.AlertPayload{
		Fingerprint: "abc",
		Title:       "host1 - Disk Usage",
		Severity:    "critical",
		Source:      "checkmk",
		Fields:      map[string]string{"hostname": "host1", "host_address": "10.0.0.1"},
	}

	ProcessAlert(context.Background(), deps, alert)

	if metrics.AlertsProcessed.Load() != 1 {
		t.Errorf("AlertsProcessed = %d, want 1", metrics.AlertsProcessed.Load())
	}
	if len(pub.published) != 1 || pub.published[0] != "disk full analysis" {
		t.Errorf("published = %v", pub.published)
	}
}

func TestProcessAlert_AnalysisFails_CooldownCleared(t *testing.T) {
	pub := &mockPublisher{}
	cooldown := shared.NewCooldownManager()
	metrics := new(shared.AlertMetrics)

	deps := PipelineDeps{
		Analyzer:   &mockAnalyzer{err: context.DeadlineExceeded},
		Publishers: []shared.Publisher{pub},
		Cooldown:   cooldown,
		Metrics:    metrics,
		SSHEnabled: false,
		GatherContext: func(ctx context.Context, alert shared.AlertPayload, hostInfo *HostInfo) shared.AnalysisContext {
			return shared.AnalysisContext{}
		},
		ValidateHost: func(ctx context.Context, hostname, hostAddress string) (*HostInfo, error) {
			return nil, nil
		},
	}

	alert := shared.AlertPayload{Fingerprint: "abc", Title: "Test", Severity: "warning", Fields: map[string]string{"hostname": "h", "host_address": "1.2.3.4"}}
	ProcessAlert(context.Background(), deps, alert)

	if metrics.AlertsFailed.Load() != 1 {
		t.Errorf("AlertsFailed = %d, want 1", metrics.AlertsFailed.Load())
	}
}
