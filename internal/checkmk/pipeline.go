package checkmk

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
)

// PipelineDeps holds all dependencies for CheckMK alert processing.
//
// Invariants: Analyzer, ToolRunner, Policy, Cooldown, Metrics, GatherContext,
// and ValidateHost must all be non-nil. SSHDialer must be non-nil when
// SSHEnabled is true. Construction in cmd/checkmk-analyzer validates this
// at startup; the pipeline does not re-check at runtime.
type PipelineDeps struct {
	// Analyzer is used for the static-only path (rounds==0 or sshOK==false):
	// no SSH tool, just the gathered context. In production both Analyzer and
	// ToolRunner point at the same *shared.ClaudeClient.
	Analyzer   shared.Analyzer
	ToolRunner shared.ToolLoopRunner
	Publishers []shared.Publisher
	Cooldown   *shared.CooldownManager
	Metrics    *shared.AlertMetrics
	SSHEnabled bool
	SSHDialer  Dialer
	SSHConfig  Config
	// Policy decides per-alert model and tool-loop budget keyed on
	// alert.SeverityLevel. A round budget of 0 routes to Analyzer.Analyze
	// even when SSH is available.
	Policy        *shared.AnalysisPolicy
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
	// Sanitize the alert title once here so that all downstream uses —
	// notification titles, notification bodies, log fields, and the Claude
	// prompt — are free of embedded control characters. The alert.Title is
	// derived from the webhook hostname and service_description, both of
	// which are sanitized in GatherContext when they appear in the Claude
	// prompt. NtfyPublisher.Publish sanitizes the HTTP title header itself,
	// but other Publisher implementations may not, so we sanitize here
	// before all uses (both title and body arguments to PublishAll).
	safeTitle := shared.SanitizeAlertField(alert.Title)

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

	model := deps.Policy.ModelFor(alert.SeverityLevel)
	rounds := deps.Policy.MaxRoundsFor(alert.SeverityLevel)

	var (
		analysis string
		err      error
	)
	if rounds > 0 && sshOK {
		analysis, err = RunAgenticDiagnostics(ctx, deps.SSHConfig, deps.ToolRunner, deps.SSHDialer, deps.Metrics, hostname, hostInfo.VerifiedIP, alertContext, rounds, model)
	} else {
		analysis, err = deps.Analyzer.Analyze(ctx, model, StaticAnalysisSystemPrompt, alertContext)
	}
	if err != nil {
		slog.Error("analysis failed", "hostname", hostname, "error", err)
		deps.Metrics.RecordClaudeAPIError(alert.Source)
		if notifyErr := shared.PublishAll(ctx, deps.Publishers,
			fmt.Sprintf("Analysis FAILED: %s", safeTitle), "5",
			fmt.Sprintf("**Analysis failed** for %s: %v\n\nManual investigation needed.", safeTitle, err)); notifyErr != nil {
			slog.Warn("failed to publish failure notification", "hostname", hostname, "error", notifyErr)
		}
		deps.Cooldown.Clear(alert.Fingerprint)
		deps.Metrics.AlertsFailed.Add(1)
		return
	}

	if analysis == "" {
		slog.Warn("analysis returned empty result, treating as failure", "hostname", hostname)
		if notifyErr := shared.PublishAll(ctx, deps.Publishers,
			fmt.Sprintf("Analysis FAILED: %s", safeTitle), "5",
			fmt.Sprintf("**Analysis produced empty result** for %s.\n\nManual investigation needed.", safeTitle)); notifyErr != nil {
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

	title := fmt.Sprintf("Analysis: %s", safeTitle)
	if err := shared.PublishAll(ctx, deps.Publishers, title, priority, analysis); err != nil {
		slog.Error("failed to publish analysis", "hostname", hostname, "error", err)
		deps.Metrics.RecordNtfyPublishError(alert.Source)
		deps.Cooldown.Clear(alert.Fingerprint)
		deps.Metrics.AlertsFailed.Add(1)
		return
	}

	deps.Metrics.AlertsProcessed.Add(1)
	deps.Metrics.RecordAnalyzed(alert.Source, alert.Severity)
	slog.Info("analysis complete", "hostname", hostname)
}
