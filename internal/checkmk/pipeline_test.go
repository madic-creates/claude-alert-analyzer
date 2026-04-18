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
	result           string
	err              error
	capturedPrompt   string
}

func (m *mockAnalyzer) Analyze(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	m.capturedPrompt = systemPrompt
	return m.result, m.err
}

func (m *mockAnalyzer) RunToolLoop(ctx context.Context, systemPrompt, userPrompt string,
	tools []shared.Tool, maxRounds int, handleTool func(string, json.RawMessage) (string, error)) (string, error) {
	m.capturedPrompt = systemPrompt
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
	if bodies := pub.published(); len(bodies) != 1 || bodies[0] != "disk full analysis" {
		t.Errorf("published = %v", bodies)
	}
}

// mockDialer records the host passed to Dial so tests can assert it.
type mockDialer struct {
	dialedHost string
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

// TestProcessAlert_SSH_Success verifies the happy path when SSH is enabled,
// host validation passes, and RunAgenticDiagnostics returns an analysis.
// The analysis must be published with the correct title/priority and
// AlertsProcessed must be incremented.
func TestProcessAlert_SSH_Success(t *testing.T) {
	// Start a real in-process SSH server so RunAgenticDiagnostics can connect.
	sshClient := startTestSSHServer(t, func(_ string, ch ssh.Channel) {
		sendExitStatus(ch, 0)
	})
	dialer := &fixedDialer{client: sshClient}

	runner := &capturingToolRunner{result: "ssh agentic analysis"}
	pub := &mockPublisher{}
	cooldown := shared.NewCooldownManager()
	metrics := new(shared.AlertMetrics)

	deps := PipelineDeps{
		Analyzer:   &mockAnalyzer{result: "fallback"},
		ToolRunner: runner,
		Publishers: []shared.Publisher{pub},
		Cooldown:   cooldown,
		Metrics:    metrics,
		SSHEnabled: true,
		SSHDialer:  dialer,
		SSHConfig:  Config{MaxAgentRounds: 3, SSHDeniedCommands: DefaultDeniedCommands},
		GatherContext: func(ctx context.Context, alert shared.AlertPayload, hostInfo *HostInfo) shared.AnalysisContext {
			return shared.AnalysisContext{Sections: []shared.ContextSection{{Name: "Test", Content: "data"}}}
		},
		ValidateHost: func(ctx context.Context, hostname, hostAddress string) (*HostInfo, error) {
			return &HostInfo{}, nil
		},
	}

	alert := shared.AlertPayload{
		Fingerprint: "ssh-success-fp",
		Title:       "host1 - High Load",
		Severity:    "warning",
		Fields:      map[string]string{"hostname": "host1", "host_address": "10.0.0.1"},
	}

	ProcessAlert(context.Background(), deps, alert)

	if metrics.AlertsProcessed.Load() != 1 {
		t.Errorf("AlertsProcessed = %d, want 1", metrics.AlertsProcessed.Load())
	}
	if metrics.AlertsFailed.Load() != 0 {
		t.Errorf("AlertsFailed = %d, want 0", metrics.AlertsFailed.Load())
	}
	if len(pub.calls) != 1 {
		t.Fatalf("expected 1 publish call, got %d", len(pub.calls))
	}
	if pub.calls[0].body != "ssh agentic analysis" {
		t.Errorf("published body = %q, want %q", pub.calls[0].body, "ssh agentic analysis")
	}
	if pub.calls[0].title != "Analysis: host1 - High Load" {
		t.Errorf("published title = %q, want %q", pub.calls[0].title, "Analysis: host1 - High Load")
	}
	if pub.calls[0].priority != "4" { // "warning" → "4"
		t.Errorf("published priority = %q, want %q", pub.calls[0].priority, "4")
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

// TestProcessAlert_PublishFails verifies that when PublishAll returns an error
// the cooldown is cleared (so the alert can be retried) and AlertsFailed is
// incremented.
func TestProcessAlert_PublishFails(t *testing.T) {
	pub := &mockPublisher{err: fmt.Errorf("ntfy unavailable")}
	cooldown := shared.NewCooldownManager()
	metrics := new(shared.AlertMetrics)

	deps := PipelineDeps{
		Analyzer:   &mockAnalyzer{result: "disk analysis"},
		Publishers: []shared.Publisher{pub},
		Cooldown:   cooldown,
		Metrics:    metrics,
		SSHEnabled: false,
		GatherContext: func(ctx context.Context, alert shared.AlertPayload, hostInfo *HostInfo) shared.AnalysisContext {
			return shared.AnalysisContext{}
		},
		ValidateHost: func(ctx context.Context, hostname, hostAddress string) (*HostInfo, error) {
			return &HostInfo{}, nil
		},
	}

	alert := shared.AlertPayload{Fingerprint: "fp1", Title: "DiskFull", Severity: "critical", Fields: map[string]string{"hostname": "h", "host_address": "1.2.3.4"}}
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

// TestProcessAlert_EmptyAnalysis verifies that when Analyze returns ("", nil) —
// which can happen if Claude produces no text content blocks — the pipeline
// treats it as a failure: cooldown is cleared and AlertsFailed is incremented.
func TestProcessAlert_EmptyAnalysis(t *testing.T) {
	pub := &mockPublisher{}
	cooldown := shared.NewCooldownManager()
	metrics := new(shared.AlertMetrics)

	deps := PipelineDeps{
		Analyzer:   &mockAnalyzer{result: "", err: nil},
		Publishers: []shared.Publisher{pub},
		Cooldown:   cooldown,
		Metrics:    metrics,
		SSHEnabled: false,
		GatherContext: func(ctx context.Context, alert shared.AlertPayload, hostInfo *HostInfo) shared.AnalysisContext {
			return shared.AnalysisContext{}
		},
		ValidateHost: func(ctx context.Context, hostname, hostAddress string) (*HostInfo, error) {
			return &HostInfo{}, nil
		},
	}

	alert := shared.AlertPayload{
		Fingerprint: "fp-empty",
		Title:       "EmptyAlert",
		Severity:    "warning",
		Fields:      map[string]string{"hostname": "host1", "host_address": "10.0.0.1"},
	}
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

// TestProcessAlert_PriorityMapping verifies the checkmk severity → ntfy priority
// table and that an unrecognised severity falls back to "3".
func TestProcessAlert_PriorityMapping(t *testing.T) {
	cases := []struct {
		severity string
		want     string
	}{
		{"critical", "5"},
		{"warning", "4"},
		{"unknown", "3"},
		{"ok", "2"},
		{"", "3"},         // empty → default
		{"CRITICAL", "3"}, // case-sensitive → default
	}

	for _, tc := range cases {
		tc := tc
		t.Run(fmt.Sprintf("severity=%q", tc.severity), func(t *testing.T) {
			pub := &mockPublisher{}
			metrics := new(shared.AlertMetrics)

			deps := PipelineDeps{
				Analyzer:   &mockAnalyzer{result: "analysis"},
				Publishers: []shared.Publisher{pub},
				Cooldown:   shared.NewCooldownManager(),
				Metrics:    metrics,
				SSHEnabled: false,
				GatherContext: func(ctx context.Context, alert shared.AlertPayload, hostInfo *HostInfo) shared.AnalysisContext {
					return shared.AnalysisContext{}
				},
				ValidateHost: func(ctx context.Context, hostname, hostAddress string) (*HostInfo, error) {
					return &HostInfo{}, nil
				},
			}

			alert := shared.AlertPayload{
				Fingerprint: "fp-" + tc.severity,
				Title:       "TestAlert",
				Severity:    tc.severity,
				Fields:      map[string]string{"hostname": "h", "host_address": "1.2.3.4"},
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

// TestProcessAlert_TitleFormatting verifies the published title format.
func TestProcessAlert_TitleFormatting(t *testing.T) {
	pub := &mockPublisher{}
	metrics := new(shared.AlertMetrics)

	deps := PipelineDeps{
		Analyzer:   &mockAnalyzer{result: "analysis"},
		Publishers: []shared.Publisher{pub},
		Cooldown:   shared.NewCooldownManager(),
		Metrics:    metrics,
		SSHEnabled: false,
		GatherContext: func(ctx context.Context, alert shared.AlertPayload, hostInfo *HostInfo) shared.AnalysisContext {
			return shared.AnalysisContext{}
		},
		ValidateHost: func(ctx context.Context, hostname, hostAddress string) (*HostInfo, error) {
			return &HostInfo{}, nil
		},
	}

	alert := shared.AlertPayload{
		Fingerprint: "fp-title",
		Title:       "High CPU Usage",
		Severity:    "warning",
		Fields:      map[string]string{"hostname": "web01", "host_address": "10.0.0.1"},
	}
	ProcessAlert(context.Background(), deps, alert)

	if len(pub.calls) != 1 {
		t.Fatalf("expected 1 publish call, got %d", len(pub.calls))
	}
	wantTitle := "Analysis: High CPU Usage"
	if pub.calls[0].title != wantTitle {
		t.Errorf("title = %q, want %q", pub.calls[0].title, wantTitle)
	}
}

// TestProcessAlert_PanicClearsCooldown verifies that a panic inside ProcessAlert
// (e.g. a nil-pointer in context gathering or analysis) clears the cooldown so
// the next webhook can trigger a retry rather than being silently dropped for the TTL.
func TestProcessAlert_PanicClearsCooldown(t *testing.T) {
	pub := &mockPublisher{}
	cooldown := shared.NewCooldownManager()
	metrics := new(shared.AlertMetrics)

	deps := PipelineDeps{
		Analyzer:   &panicAnalyzer{},
		Publishers: []shared.Publisher{pub},
		Cooldown:   cooldown,
		Metrics:    metrics,
		SSHEnabled: false,
		GatherContext: func(ctx context.Context, alert shared.AlertPayload, hostInfo *HostInfo) shared.AnalysisContext {
			return shared.AnalysisContext{}
		},
		ValidateHost: func(ctx context.Context, hostname, hostAddress string) (*HostInfo, error) {
			return &HostInfo{}, nil
		},
	}

	alert := shared.AlertPayload{
		Fingerprint: "panic-fp",
		Title:       "Test",
		Severity:    "warning",
		Fields:      map[string]string{"hostname": "host1", "host_address": "10.0.0.1"},
	}

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

// TestProcessAlert_NoSSH_UsesStaticPrompt verifies that when SSH is disabled the
// pipeline calls Analyze with StaticAnalysisSystemPrompt. The agentic prompt
// instructs Claude to use SSH tool-use; sending it without tools
// produces misleading output ("I would run ssh...").
func TestProcessAlert_NoSSH_UsesStaticPrompt(t *testing.T) {
	analyzer := &mockAnalyzer{result: "analysis"}
	pub := &mockPublisher{}
	cooldown := shared.NewCooldownManager()
	metrics := new(shared.AlertMetrics)

	deps := PipelineDeps{
		Analyzer:   analyzer,
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
		Fingerprint: "prompt-check",
		Title:       "DiskUsage",
		Severity:    "warning",
		Fields:      map[string]string{"hostname": "host1", "host_address": "10.0.0.1"},
	}

	ProcessAlert(context.Background(), deps, alert)

	if analyzer.capturedPrompt != StaticAnalysisSystemPrompt {
		t.Errorf("no-SSH path used wrong system prompt; got %q, want StaticAnalysisSystemPrompt", analyzer.capturedPrompt)
	}
}
