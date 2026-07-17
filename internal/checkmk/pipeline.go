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
//
// Breaker, StormNotify, and BreakerNotify are optional Phase 2 fields. nil is
// the disabled-default and all access sites are nil-safe.
type PipelineDeps struct {
	// Analyzer is used for the static-only path (rounds==0 or sshOK==false):
	// no SSH tool, just the gathered context. In production both Analyzer and
	// ToolRunner point at the same *shared.ClaudeClient.
	Analyzer   shared.Analyzer
	ToolRunner shared.ToolLoopRunner
	Publishers []shared.Publisher
	Cooldown   *shared.CooldownManager
	Metrics    *shared.AlertMetrics
	// Policy decides per-alert model and tool-loop budget keyed on
	// alert.SeverityLevel. A round budget of 0 routes to Analyzer.Analyze
	// even when SSH is available.
	Policy *shared.AnalysisPolicy
	// Breaker gates logical analysis attempts. nil ↔ disabled (no-op permits).
	Breaker *shared.CircuitBreaker
	// StormNotify aggregates per-alert notifications during storm-mode.
	// nil ↔ no aggregation (per-alert publish on the success path).
	StormNotify *shared.NotifyAggregator
	// BreakerNotify aggregates per-alert notifications when the breaker is open.
	// nil ↔ no aggregation (alert silently dropped on ErrCircuitOpen).
	BreakerNotify *shared.NotifyAggregator
	SSHEnabled    bool
	SSHDialer     Dialer
	SSHConfig     Config
	GatherContext func(ctx context.Context, alert shared.AlertPayload, hostInfo *HostInfo) shared.AnalysisContext
	ValidateHost  func(ctx context.Context, hostname, hostAddress string) (*HostInfo, error)

	History            shared.HistoryStore
	HistoryInjectPrior bool
}

// sharedDeps maps the product deps onto the shared orchestration deps.
func (d PipelineDeps) sharedDeps() shared.PipelineDeps {
	return shared.PipelineDeps{
		Publishers:         d.Publishers,
		Cooldown:           d.Cooldown,
		Metrics:            d.Metrics,
		Policy:             d.Policy,
		Breaker:            d.Breaker,
		StormNotify:        d.StormNotify,
		BreakerNotify:      d.BreakerNotify,
		History:            d.History,
		HistoryInjectPrior: d.HistoryInjectPrior,
	}
}

// pipelineHooks adapts the CheckMK-specific behavior to shared.ProcessAlert.
type pipelineHooks struct {
	deps PipelineDeps
}

// DisplayName sanitizes the alert title once so that all downstream uses —
// notification titles, notification bodies, and log fields — are free of
// embedded control characters. The alert.Title is derived from the webhook
// hostname and service_description, both of which are sanitized in
// GatherContext when they appear in the Claude prompt. NtfyPublisher.Publish
// sanitizes the HTTP title header itself, but other Publisher implementations
// may not, so sanitize here before all uses.
func (pipelineHooks) DisplayName(alert shared.AlertPayload) string {
	return shared.SanitizeAlertField(alert.Title)
}

func (pipelineHooks) LogArgs(alert shared.AlertPayload) []any {
	return []any{
		"hostname", alert.Fields["hostname"],
		"service", alert.Fields["service_description"],
	}
}

func (pipelineHooks) NotifyTitle(alert shared.AlertPayload) string {
	return fmt.Sprintf("Analysis: %s", shared.SanitizeAlertField(alert.Title))
}

func (h pipelineHooks) Prepare(ctx context.Context, alert shared.AlertPayload, inject func(shared.AnalysisContext) shared.AnalysisContext) shared.AnalyzeFunc {
	deps := h.deps
	hostname := alert.Fields["hostname"]
	hostAddress := alert.Fields["host_address"]

	hostInfo, validationErr := deps.ValidateHost(ctx, hostname, hostAddress)
	if validationErr != nil {
		slog.Warn("host validation failed", "error", validationErr, "hostname", hostname, "host_address", hostAddress)
	}

	gatherStart := time.Now()
	actx := deps.GatherContext(ctx, alert, hostInfo)
	deps.Metrics.ObserveContextGatherDuration(time.Since(gatherStart))
	actx = inject(actx)
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

	return func(ctx context.Context, model string, rounds int) (string, error) {
		if rounds > 0 && sshOK {
			return RunAgenticDiagnostics(ctx, deps.SSHConfig, deps.ToolRunner, deps.SSHDialer, deps.Metrics, alert.SeverityLevel, hostname, hostInfo.VerifiedIP, alertContext, rounds, model)
		}
		return deps.Analyzer.Analyze(ctx, alert.SeverityLevel, model, StaticAnalysisSystemPrompt, alertContext)
	}
}

// ProcessAlert gathers context, optionally runs agentic SSH diagnostics, and
// publishes results. The orchestration (failure phases, breaker permits,
// cooldown cleanup, storm handling) lives in shared.ProcessAlert; this
// adapter supplies the CheckMK-specific hooks.
func ProcessAlert(ctx context.Context, deps PipelineDeps, alert shared.AlertPayload) {
	shared.ProcessAlert(ctx, deps.sharedDeps(), pipelineHooks{deps: deps}, alert)
}
