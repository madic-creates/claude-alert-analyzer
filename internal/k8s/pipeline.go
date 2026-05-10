package k8s

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

// PipelineDeps holds all dependencies for k8s alert processing.
//
// Invariants: Analyzer, ToolRunner, Policy, Cooldown, Metrics, GatherContext,
// KubectlRunner, and Prom must all be non-nil. Construction in cmd/k8s-analyzer
// validates this at startup; the pipeline does not re-check at runtime.
//
// Breaker, StormNotify, and BreakerNotify are optional Phase 2 fields. nil is
// the disabled-default and all access sites are nil-safe.
type PipelineDeps struct {
	// Analyzer is used for the static-only path (rounds==0): no kubectl/promql
	// tools, just the gathered context. In production both Analyzer and
	// ToolRunner point at the same *shared.ClaudeClient.
	Analyzer      shared.Analyzer
	ToolRunner    shared.ToolLoopRunner
	KubectlRunner KubectlRunner
	Prom          PromQLQuerier
	Publishers    []shared.Publisher
	Cooldown      *shared.CooldownManager
	Metrics       *shared.AlertMetrics
	// Policy decides per-alert model and tool-loop budget keyed on
	// alert.SeverityLevel. A round budget of 0 routes to Analyzer.Analyze.
	Policy *shared.AnalysisPolicy
	// Breaker gates logical analysis attempts. nil ↔ disabled (no-op permits).
	Breaker *shared.CircuitBreaker
	// StormNotify aggregates per-alert notifications during storm-mode.
	// nil ↔ no aggregation (per-alert publish on the success path).
	StormNotify *shared.NotifyAggregator
	// BreakerNotify aggregates per-alert notifications when the breaker is open.
	// nil ↔ no aggregation (alert silently dropped on ErrCircuitOpen).
	BreakerNotify *shared.NotifyAggregator
	GatherContext func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext
}

// ProcessAlert gathers context, analyzes via Claude, and publishes results.
//
// Failure-phase cleanup: a separate analysisErr variable is used inside the
// defer so a post-API publish error (which sets the named return err) cannot
// flip the phase decision. See spec section 2.1.
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
		// errors. Both Done() and analysisErr are set by this point — see comment
		// above. permit may be nil if Acquire() failed in the API phase.
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

	// Sanitize at the point of extraction so that all downstream uses —
	// failure notification bodies, log fields, and the Claude prompt — are
	// free of control characters. The Claude userPrompt already applied
	// SanitizeAlertField to alertname, but the failure-notification bodies
	// passed it unsanitized, allowing embedded newlines or other C0 control
	// characters from a crafted Alertmanager webhook to corrupt notification
	// content. Sanitizing once here is simpler than at every call site.
	alertname := shared.SanitizeAlertField(alert.Title)
	namespace := shared.SanitizeAlertField(alert.Fields["label:namespace"])
	slog.Info("processing alert", "alertname", alertname, "namespace", namespace)

	// === Pre-API phase ===
	actx := deps.GatherContext(ctx, alert)
	userPrompt := fmt.Sprintf("## Alert: %s\n- Status: %s\n- Severity: %s\n- Namespace: %s\n- StartsAt: %s\n\n%s",
		alertname,
		shared.SanitizeAlertField(alert.Fields["status"]),
		shared.SanitizeAlertField(alert.Severity),
		namespace,
		shared.SanitizeAlertField(alert.Fields["startsAt"]),
		actx.FormatForPrompt())

	// Update breaker-state metric on every alert so Grafana sees the gauge fresh.
	if deps.Breaker != nil {
		deps.Metrics.SetBreakerState(deps.Breaker.State())
	}
	deps.Metrics.SetStormMode(deps.Policy.IsDegraded())

	// === Acquire breaker permit ===
	phase = phaseAPI
	var err error
	permit, err = deps.Breaker.Acquire()
	if err != nil {
		analysisErr = err
		// Aggregate the alert into the breaker-aggregator instead of per-alert ntfy.
		if deps.BreakerNotify != nil {
			deps.BreakerNotify.Add(alertname)
		}
		slog.Warn("breaker open, dropping analysis", "alertname", alertname)
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
	if deps.Policy.IsDegraded() || permit.IsProbe() {
		rounds = 0
	}

	var analysis string
	if rounds == 0 {
		analysis, analysisErr = deps.Analyzer.Analyze(ctx, alert.SeverityLevel, model, StaticAnalysisSystemPrompt, userPrompt)
	} else {
		analysis, analysisErr = RunAgenticDiagnostics(ctx, deps.ToolRunner, deps.KubectlRunner, deps.Prom, deps.Metrics, alert.SeverityLevel, userPrompt, rounds, model)
	}
	if analysisErr != nil {
		slog.Error("analysis failed", "alertname", alertname, "error", analysisErr)
		deps.Metrics.RecordClaudeAPIError()
		if notifyErr := shared.PublishAll(ctx, deps.Publishers,
			fmt.Sprintf("Analysis FAILED: %s", alertname), "5",
			fmt.Sprintf("**Analysis failed** for %s: %s\n\nManual investigation needed.", alertname, shared.RedactSecrets(shared.SanitizeAlertField(analysisErr.Error())))); notifyErr != nil {
			slog.Warn("failed to publish failure notification", "alertname", alertname, "error", notifyErr)
		}
		return
	}
	if analysis == "" {
		analysisErr = errors.New("empty analysis")
		slog.Warn("analysis returned empty result, treating as failure", "alertname", alertname)
		if notifyErr := shared.PublishAll(ctx, deps.Publishers,
			fmt.Sprintf("Analysis FAILED: %s", alertname), "5",
			fmt.Sprintf("**Analysis produced empty result** for %s.\n\nManual investigation needed.", alertname)); notifyErr != nil {
			slog.Warn("failed to publish failure notification", "alertname", alertname, "error", notifyErr)
		}
		return
	}

	// === Post-API phase ===
	phase = phasePostAPI

	title := fmt.Sprintf("Analysis: %s", alertname)
	if namespace != "" {
		title = fmt.Sprintf("Analysis: %s (%s)", alertname, namespace)
	}
	// Use the normalized SeverityLevel (not the raw alert.Severity label) so
	// that non-standard Alertmanager severity values such as "page" (→ critical)
	// and "notice" (→ warning) map to the correct ntfy priority. alert.Severity
	// holds the raw label from the webhook and may not match the priority-map
	// keys; SeverityLevel is always one of the four normalized enum values.
	priorityMap := map[string]string{"critical": "5", "warning": "4", "info": "2", "unknown": "3"}
	priority := priorityMap[alert.SeverityLevel.String()]

	if deps.Policy.IsDegraded() && deps.StormNotify != nil {
		deps.StormNotify.Add(alertname)
	} else if pubErr := shared.PublishAll(ctx, deps.Publishers, title, priority, analysis); pubErr != nil {
		slog.Error("failed to publish analysis", "alertname", alertname, "error", pubErr)
		deps.Metrics.RecordNtfyPublishError()
		// Phase is already phasePostAPI — defer keeps cooldowns. RecordFailed
		// is the operator-visible signal.
		deps.Metrics.RecordFailed()
		return
	}

	deps.Metrics.RecordProcessed(alert.SeverityLevel)
	slog.Info("analysis complete", "alertname", alertname)
}
