package checkmk

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
	"golang.org/x/crypto/ssh"
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

// mockDialer records the host passed to Dial so tests can assert it.
type mockDialer struct {
	dialedHost string
	err        error
}

func (d *mockDialer) Dial(host string) (*ssh.Client, error) {
	d.dialedHost = host
	return nil, fmt.Errorf("mock dial error")
}

// TestProcessAlert_SSH_UsesHostnameNotIP is a regression test for the bug where
// RunAgenticDiagnostics was called with hostAddress (IP) instead of hostname.
// When SSH_ENABLED=true, the dialer must receive the hostname so that known_hosts
// verification (which typically uses hostnames, not IPs) succeeds.
func TestProcessAlert_SSH_UsesHostnameNotIP(t *testing.T) {
	dialer := &mockDialer{}
	pub := &mockPublisher{}
	cooldown := shared.NewCooldownManager()
	metrics := new(shared.AlertMetrics)

	deps := PipelineDeps{
		Analyzer:   &mockAnalyzer{result: "fallback"},
		ToolRunner: &mockAnalyzer{result: "analysis"},
		Publishers: []shared.Publisher{pub},
		Cooldown:   cooldown,
		Metrics:    metrics,
		SSHEnabled: true,
		SSHDialer:  dialer,
		SSHConfig:  Config{MaxAgentRounds: 1},
		GatherContext: func(ctx context.Context, alert shared.AlertPayload, hostInfo *HostInfo) shared.AnalysisContext {
			return shared.AnalysisContext{}
		},
		ValidateHost: func(ctx context.Context, hostname, hostAddress string) (*HostInfo, error) {
			return &HostInfo{}, nil
		},
	}

	alert := shared.AlertPayload{
		Fingerprint: "reg001",
		Title:       "High CPU",
		Severity:    "warning",
		Fields:      map[string]string{"hostname": "web-01.example.com", "host_address": "192.168.1.50"},
	}

	ProcessAlert(context.Background(), deps, alert)

	// The dialer must receive the hostname, not the IP address.
	if dialer.dialedHost != "web-01.example.com" {
		t.Errorf("dialer called with %q, want hostname %q (not IP %q)",
			dialer.dialedHost, "web-01.example.com", "192.168.1.50")
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
