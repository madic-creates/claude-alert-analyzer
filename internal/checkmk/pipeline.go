package checkmk

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
)

// failurePhase tracks how far ProcessAlert progressed when an error occurred,
// so the deferred cleanup decides correctly whether to clear cooldowns.
type failurePhase int

const (
	phasePreAPI failurePhase = iota
	phaseAPI
	phasePostAPI
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

// ProcessAlert gathers context, optionally runs agentic SSH diagnostics, and publishes results.
//
// Failure-phase cleanup: a separate analysisErr variable is used inside the
// defer so a post-API publish error cannot flip the phase decision.
// See spec section 2.1.
func ProcessAlert(ctx context.Context, deps PipelineDeps, alert shared.AlertPayload) {
	start := time.Now()
	var (
		phase       = phasePreAPI
		analysisErr error
		permit      *shared.Permit
	)

	defer func() {
		deps.Metrics.ObserveProcessingDuration(time.Since(start))
	}()

	defer func() {
		// Panic-recovery: capture the panic value into analysisErr so it flows
		// into permit.Done() AND the phase-switch cooldown cleanup.
		// Without this ordering, a panic between Acquire() and the assignment
		// to analysisErr would leave analysisErr=nil and cause permit.Done(nil)
		// — the breaker would record a SUCCESS for a panicked analysis.
		if r := recover(); r != nil {
			if analysisErr == nil {
				analysisErr = fmt.Errorf("panic recovered: %v", r)
			}
			defer panic(r) // re-panic AFTER the cleanup body completes
		}
		// Settle the breaker permit FIRST so the breaker observes panics + late
		// errors. permit may be nil if Acquire() failed in the API phase.
		if permit != nil {
			permit.Done(analysisErr)
		}
		switch phase {
		case phasePreAPI:
			deps.Cooldown.Clear(alert.Fingerprint)
			if alert.GroupKey != "" {
				deps.Cooldown.ClearGroup(alert.GroupKey)
			}
			if analysisErr != nil {
				deps.Metrics.RecordFailed()
			}
		case phaseAPI:
			// analysisErr is always non-nil here: Acquire() sets it on failure,
			// and the analysis + empty-check paths set it before returning.
			if errors.Is(analysisErr, shared.ErrCircuitOpen) {
				// Verstärker-Mitigation: keep cooldowns to absorb retries.
				deps.Metrics.RecordFailed()
				return
			}
			deps.Cooldown.Clear(alert.Fingerprint)
			if alert.GroupKey != "" {
				deps.Cooldown.ClearGroup(alert.GroupKey)
			}
			deps.Metrics.RecordFailed()
		case phasePostAPI:
			// Analysis succeeded; ntfy-failure is logged separately.
			return
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

	// === Pre-API phase ===
	hostInfo, validationErr := deps.ValidateHost(ctx, hostname, hostAddress)
	if validationErr != nil {
		slog.Warn("host validation failed", "error", validationErr, "hostname", hostname, "host_address", hostAddress)
	}

	actx := deps.GatherContext(ctx, alert, hostInfo)
	var historyView shared.HistoryView
	actx, historyView = shared.InjectHistory(ctx, deps.History, alert.Fingerprint, deps.HistoryInjectPrior, actx)
	if historyView.Count > 1 {
		deps.Metrics.ObserveRecurrence(historyView.Count)
	}
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

	// Snapshot storm-mode once so the rounds decision and the publish decision
	// see a consistent value. IsDegraded() queries the sliding-window counter
	// which can change between calls as concurrent alerts arrive; if storm mode
	// turns on after we decide rounds>0 but before we reach the publish step,
	// an expensive agentic analysis result would be silently collapsed to just a
	// title in the StormNotify aggregator.
	stormMode := deps.Policy.IsDegraded()

	// Update breaker-state and storm-mode metrics on every alert so Grafana
	// sees the gauges fresh.
	if deps.Breaker != nil {
		deps.Metrics.SetBreakerState(deps.Breaker.State())
	}
	deps.Metrics.SetStormMode(stormMode)

	// === Acquire breaker permit ===
	phase = phaseAPI
	var err error
	permit, err = deps.Breaker.Acquire()
	if err != nil {
		analysisErr = err
		// Aggregate the alert into the breaker-aggregator instead of per-alert ntfy.
		if deps.BreakerNotify != nil {
			deps.BreakerNotify.Add(safeTitle)
		}
		slog.Warn("breaker open, dropping analysis", "hostname", hostname)
		// Note: claude_api_errors_total is NOT incremented here — ErrCircuitOpen
		// is a pre-flight rejection, not a Claude-API failure. The
		// claude_circuit_breaker_state gauge plus notify_aggregator_drops_total
		// {aggregator="breaker"} cover this case for operators.
		return
	}
	// Settling the permit happens in the cleanup defer above so the breaker
	// observes panics that occur between this point and the analysis assignment.

	model := deps.Policy.ModelFor(alert.SeverityLevel)
	rounds := deps.Policy.MaxRoundsFor(alert.SeverityLevel)
	if stormMode || permit.IsProbe() {
		rounds = 0
	}

	var analysis string
	if rounds > 0 && sshOK {
		analysis, analysisErr = RunAgenticDiagnostics(ctx, deps.SSHConfig, deps.ToolRunner, deps.SSHDialer, deps.Metrics, alert.SeverityLevel, hostname, hostInfo.VerifiedIP, alertContext, rounds, model)
	} else {
		analysis, analysisErr = deps.Analyzer.Analyze(ctx, alert.SeverityLevel, model, StaticAnalysisSystemPrompt, alertContext)
	}
	if analysisErr != nil {
		slog.Error("analysis failed", "hostname", hostname, "error", analysisErr)
		deps.Metrics.RecordClaudeAPIError()
		if notifyErr := shared.PublishAll(ctx, deps.Publishers,
			fmt.Sprintf("Analysis FAILED: %s", safeTitle), "5",
			fmt.Sprintf("**Analysis failed** for %s: %s\n\nManual investigation needed.", safeTitle, shared.SanitizeAlertField(shared.RedactSecrets(analysisErr.Error())))); notifyErr != nil {
			slog.Warn("failed to publish failure notification", "hostname", hostname, "error", notifyErr)
		}
		return
	}
	if analysis == "" {
		analysisErr = errors.New("empty analysis")
		slog.Warn("analysis returned empty result, treating as failure", "hostname", hostname)
		if notifyErr := shared.PublishAll(ctx, deps.Publishers,
			fmt.Sprintf("Analysis FAILED: %s", safeTitle), "5",
			fmt.Sprintf("**Analysis produced empty result** for %s.\n\nManual investigation needed.", safeTitle)); notifyErr != nil {
			slog.Warn("failed to publish failure notification", "hostname", hostname, "error", notifyErr)
		}
		return
	}

	// === Post-API phase ===
	phase = phasePostAPI

	priorityMap := map[string]string{"critical": "5", "warning": "4", "info": "2", "unknown": "3"}
	priority := priorityMap[alert.SeverityLevel.String()]
	title := fmt.Sprintf("Analysis: %s", safeTitle)

	if stormMode && deps.StormNotify != nil {
		deps.StormNotify.Add(safeTitle)
	} else if pubErr := shared.PublishAll(ctx, deps.Publishers, title, priority, analysis); pubErr != nil {
		slog.Error("failed to publish analysis", "hostname", hostname, "error", pubErr)
		deps.Metrics.RecordNtfyPublishError()
		// Phase is already phasePostAPI — defer keeps cooldowns. RecordFailed
		// is the operator-visible signal.
		deps.Metrics.RecordFailed()
		return
	}

	deps.Metrics.RecordProcessed(alert.SeverityLevel)
	slog.Info("analysis complete", "hostname", hostname)
}
