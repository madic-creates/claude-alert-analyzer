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
	// If any step panics, clear the cooldown so the next webhook triggers a
	// retry instead of silently skipping the alert for the entire TTL.
	defer func() {
		if r := recover(); r != nil {
			deps.Cooldown.Clear(alert.Fingerprint)
			deps.Metrics.AlertsFailed.Add(1)
			panic(r) // re-panic so safeProcess can log the stack trace
		}
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

	// hostInfo must be non-nil to access VerifiedIP for SSH dialing.
	// ValidateHost implementations should always return a non-nil *HostInfo
	// on success, but guard here to avoid a nil-pointer panic if they do not.
	sshOK := deps.SSHEnabled && validationErr == nil && hostInfo != nil
	if deps.SSHEnabled && !sshOK {
		// Do not include the raw validation error in the Claude prompt: it
		// contains untrusted values from the webhook payload (hostname,
		// host_address) that could be used for prompt injection.
		alertContext += "\n## Note\nSSH diagnostics unavailable: host validation failed\n"
	}

	var analysis string

	if sshOK {
		var err error
		analysis, err = RunAgenticDiagnostics(ctx, deps.SSHConfig, deps.ToolRunner, deps.SSHDialer, hostname, hostInfo.VerifiedIP, alertContext, deps.SSHConfig.MaxAgentRounds)
		if err != nil {
			slog.Error("agentic diagnostics failed", "error", err)
			deps.Metrics.RecordClaudeAPIError(alert.Source)
			if notifyErr := shared.PublishAll(ctx, deps.Publishers,
				fmt.Sprintf("Analysis FAILED: %s", alert.Title), "5",
				fmt.Sprintf("**Agentic diagnostics failed** for %s: %v\n\nManual investigation needed.", alert.Title, err)); notifyErr != nil {
				slog.Warn("failed to publish failure notification", "hostname", hostname, "error", notifyErr)
			}
			deps.Cooldown.Clear(alert.Fingerprint)
			deps.Metrics.AlertsFailed.Add(1)
			return
		}
	} else {
		var err error
		analysis, err = deps.Analyzer.Analyze(ctx, StaticAnalysisSystemPrompt, alertContext)
		if err != nil {
			slog.Error("analysis failed", "error", err)
			deps.Metrics.RecordClaudeAPIError(alert.Source)
			if notifyErr := shared.PublishAll(ctx, deps.Publishers,
				fmt.Sprintf("Analysis FAILED: %s", alert.Title), "5",
				fmt.Sprintf("**Analysis failed** for %s: %v\n\nManual investigation needed.", alert.Title, err)); notifyErr != nil {
				slog.Warn("failed to publish failure notification", "hostname", hostname, "error", notifyErr)
			}
			deps.Cooldown.Clear(alert.Fingerprint)
			deps.Metrics.AlertsFailed.Add(1)
			return
		}
	}

	if analysis == "" {
		slog.Warn("analysis returned empty result, treating as failure", "hostname", hostname)
		if notifyErr := shared.PublishAll(ctx, deps.Publishers,
			fmt.Sprintf("Analysis FAILED: %s", alert.Title), "5",
			fmt.Sprintf("**Analysis produced empty result** for %s.\n\nManual investigation needed.", alert.Title)); notifyErr != nil {
			slog.Warn("failed to publish failure notification", "hostname", hostname, "error", notifyErr)
		}
		deps.Cooldown.Clear(alert.Fingerprint)
		deps.Metrics.AlertsFailed.Add(1)
		return
	}

	priorityMap := map[string]string{"critical": "5", "warning": "4", "unknown": "3", "ok": "2"}
	priority := priorityMap[alert.Severity]
	if priority == "" {
		priority = "3"
	}

	title := fmt.Sprintf("Analysis: %s", alert.Title)
	if err := shared.PublishAll(ctx, deps.Publishers, title, priority, analysis); err != nil {
		deps.Metrics.RecordNtfyPublishError(alert.Source)
		deps.Cooldown.Clear(alert.Fingerprint)
		deps.Metrics.AlertsFailed.Add(1)
		return
	}

	deps.Metrics.AlertsProcessed.Add(1)
	deps.Metrics.RecordAnalyzed(alert.Source, alert.Severity)
	slog.Info("analysis complete", "hostname", hostname)
}
