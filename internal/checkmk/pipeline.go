package checkmk

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
)

// PipelineDeps holds all dependencies for CheckMK alert processing.
type PipelineDeps struct {
	Analyzer      shared.Analyzer
	ToolRunner    shared.ToolLoopRunner
	Publishers    []shared.Publisher
	Cooldown      *shared.CooldownManager
	Metrics       *shared.AlertMetrics
	SSHEnabled    bool
	SSHDialer     Dialer
	SSHConfig     Config
	GatherContext func(ctx context.Context, alert shared.AlertPayload, hostInfo *HostInfo) shared.AnalysisContext
	ValidateHost  func(ctx context.Context, hostname, hostAddress string) (*HostInfo, error)
}

// ProcessAlert gathers context, optionally runs agentic SSH diagnostics, and publishes results.
func ProcessAlert(ctx context.Context, deps PipelineDeps, alert shared.AlertPayload) {
	start := time.Now()
	defer func() {
		deps.Metrics.ProcessingDurationSum.Add(time.Since(start).Microseconds())
		deps.Metrics.ProcessingDurationCount.Add(1)
	}()
	hostname := alert.Fields["hostname"]
	hostAddress := alert.Fields["host_address"]

	slog.Info("processing CheckMK alert", "hostname", hostname, "service", alert.Fields["service_description"])

	hostInfo, validationErr := deps.ValidateHost(ctx, hostname, hostAddress)
	if validationErr != nil {
		slog.Warn("host validation failed", "error", validationErr, "hostname", hostname, "host_address", hostAddress)
	}

	actx := deps.GatherContext(ctx, alert, hostInfo)
	alertContext := actx.FormatForPrompt()

	sshOK := deps.SSHEnabled && validationErr == nil
	if deps.SSHEnabled && !sshOK {
		alertContext += "\n## Note\nSSH diagnostics unavailable: " + validationErr.Error() + "\n"
	}

	var analysis string

	if sshOK {
		var err error
		analysis, err = RunAgenticDiagnostics(ctx, deps.SSHConfig, deps.ToolRunner, deps.SSHDialer, hostname, alertContext, deps.SSHConfig.MaxAgentRounds)
		if err != nil {
			slog.Error("agentic diagnostics failed", "error", err)
			_ = shared.PublishAll(ctx, deps.Publishers,
				fmt.Sprintf("Analysis FAILED: %s", alert.Title), "5",
				fmt.Sprintf("**Agentic diagnostics failed** for %s: %v\n\nManual investigation needed.", alert.Title, err))
			deps.Cooldown.Clear(alert.Fingerprint)
			deps.Metrics.AlertsFailed.Add(1)
			return
		}
	} else {
		var err error
		analysis, err = deps.Analyzer.Analyze(ctx, AgentSystemPrompt, alertContext)
		if err != nil {
			slog.Error("analysis failed", "error", err)
			_ = shared.PublishAll(ctx, deps.Publishers,
				fmt.Sprintf("Analysis FAILED: %s", alert.Title), "5",
				fmt.Sprintf("**Analysis failed** for %s: %v\n\nManual investigation needed.", alert.Title, err))
			deps.Cooldown.Clear(alert.Fingerprint)
			deps.Metrics.AlertsFailed.Add(1)
			return
		}
	}

	priorityMap := map[string]string{"critical": "5", "warning": "4", "unknown": "3", "ok": "2"}
	priority := priorityMap[alert.Severity]
	if priority == "" {
		priority = "3"
	}

	title := fmt.Sprintf("Analysis: %s", alert.Title)
	if err := shared.PublishAll(ctx, deps.Publishers, title, priority, analysis); err != nil {
		deps.Cooldown.Clear(alert.Fingerprint)
		deps.Metrics.AlertsFailed.Add(1)
		return
	}

	deps.Metrics.AlertsProcessed.Add(1)
	slog.Info("analysis complete", "hostname", hostname)
}
