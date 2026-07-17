package shared

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// failurePhase tracks how far ProcessAlert progressed when an error occurred,
// so the deferred cleanup decides correctly whether to clear cooldowns.
type failurePhase int

const (
	phasePreAPI failurePhase = iota
	phaseAPI
	phasePostAPI
)

// PipelineDeps holds the product-independent dependencies for ProcessAlert.
//
// Invariants: Cooldown, Metrics, and Policy must be non-nil. Construction in
// each product's cmd/ validates this at startup; the pipeline does not
// re-check at runtime.
//
// Breaker, StormNotify, and BreakerNotify are optional Phase 2 fields. nil is
// the disabled-default and all access sites are nil-safe.
type PipelineDeps struct {
	Publishers []Publisher
	Cooldown   *CooldownManager
	Metrics    *AlertMetrics
	// Policy decides per-alert model and tool-loop budget keyed on
	// alert.SeverityLevel. A round budget of 0 routes to static analysis.
	Policy *AnalysisPolicy
	// Breaker gates logical analysis attempts. nil ↔ disabled (no-op permits).
	Breaker *CircuitBreaker
	// StormNotify aggregates per-alert notifications during storm-mode.
	// nil ↔ no aggregation (per-alert publish on the success path).
	StormNotify *NotifyAggregator
	// BreakerNotify aggregates per-alert notifications when the breaker is open.
	// nil ↔ no aggregation (alert silently dropped on ErrCircuitOpen).
	BreakerNotify *NotifyAggregator
	// History records fires/analyses and supplies recurrence context. Access
	// is nil-safe so tests that omit it keep working.
	History HistoryStore
	// HistoryInjectPrior gates the prior-analyses sub-block.
	HistoryInjectPrior bool
}

// AnalyzeFunc runs the product's analysis with the routed model and round
// budget. Returned by PipelineHooks.Prepare; the prompt and any per-alert
// state (e.g. SSH availability) are captured in the closure.
type AnalyzeFunc func(ctx context.Context, model string, rounds int) (string, error)

// PipelineHooks is the per-product strategy consumed by ProcessAlert. All
// product-specific behavior — context gathering, prompt construction, the
// static-vs-agentic analysis decision, and notification naming — lives behind
// this interface; ProcessAlert owns the correctness-critical control flow
// (failure phases, breaker permits, cooldown cleanup, storm handling).
type PipelineHooks interface {
	// DisplayName returns the sanitized alert name used in notification
	// titles/bodies and aggregator entries.
	DisplayName(alert AlertPayload) string
	// LogArgs returns product-specific slog key/value pairs appended to every
	// pipeline log line for this alert.
	LogArgs(alert AlertPayload) []any
	// Prepare runs product-specific pre-API work (validation + context
	// gathering) and returns the analysis closure. Implementations must call
	// inject on the gathered AnalysisContext before rendering the prompt so
	// the shared history block is included; inject also records the history
	// metrics. Prepare runs in the pre-API phase: a panic here keeps
	// cooldowns cleared so retries work.
	Prepare(ctx context.Context, alert AlertPayload, inject func(AnalysisContext) AnalysisContext) AnalyzeFunc
	// NotifyTitle returns the success-notification title.
	NotifyTitle(alert AlertPayload) string
}

// ProcessAlert gathers context via hooks, analyzes via Claude, and publishes
// results. It is the single orchestration shared by the k8s and checkmk
// analyzers (issue #32); the two products supply only PipelineHooks.
//
// Failure-phase cleanup: a separate analysisErr variable is used inside the
// defer so a post-API publish error cannot flip the phase decision.
// See spec section 2.1.
func ProcessAlert(ctx context.Context, deps PipelineDeps, hooks PipelineHooks, alert AlertPayload) {
	start := time.Now()
	var (
		phase       = phasePreAPI
		analysisErr error
		permit      *Permit
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
			if errors.Is(analysisErr, ErrCircuitOpen) {
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

	name := hooks.DisplayName(alert)
	logArgs := hooks.LogArgs(alert)
	slog.Info("processing alert", logArgs...)

	// === Pre-API phase ===
	inject := func(actx AnalysisContext) AnalysisContext {
		var historyView HistoryView
		actx, historyView = InjectHistory(ctx, deps.History, alert.Fingerprint, deps.HistoryInjectPrior, actx)
		if historyView.Count > 0 {
			deps.Metrics.RecordHistoryLookup(historyView.Count > 1)
		}
		if historyView.Count > 1 {
			deps.Metrics.ObserveRecurrence(historyView.Count)
		}
		return actx
	}
	analyze := hooks.Prepare(ctx, alert, inject)

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
			deps.BreakerNotify.Add(name)
		}
		slog.Warn("breaker open, dropping analysis", logArgs...)
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
	analysis, analysisErr = analyze(ctx, model, rounds)
	if analysisErr != nil {
		slog.Error("analysis failed", append([]any{"error", analysisErr}, logArgs...)...)
		deps.Metrics.RecordClaudeAPIError()
		// During a storm, collapse failure notifications through the aggregator
		// just like successes. Without this, an upstream Claude/OpenRouter outage
		// during an alert storm would emit one "Analysis FAILED" push per queued
		// alert — exactly the flood the aggregator exists to prevent (issue #51).
		if stormMode && deps.StormNotify != nil {
			deps.StormNotify.Add(fmt.Sprintf("%s (analysis failed)", name))
		} else if notifyErr := PublishAll(ctx, deps.Publishers,
			fmt.Sprintf("Analysis FAILED: %s", name), "5",
			fmt.Sprintf("**Analysis failed** for %s: %s\n\nManual investigation needed.", name, SanitizeAlertField(RedactSecrets(analysisErr.Error())))); notifyErr != nil {
			slog.Warn("failed to publish failure notification", append([]any{"error", notifyErr}, logArgs...)...)
		}
		return
	}
	if analysis == "" {
		analysisErr = errors.New("empty analysis")
		slog.Warn("analysis returned empty result, treating as failure", logArgs...)
		if stormMode && deps.StormNotify != nil {
			deps.StormNotify.Add(fmt.Sprintf("%s (analysis failed)", name))
		} else if notifyErr := PublishAll(ctx, deps.Publishers,
			fmt.Sprintf("Analysis FAILED: %s", name), "5",
			fmt.Sprintf("**Analysis produced empty result** for %s.\n\nManual investigation needed.", name)); notifyErr != nil {
			slog.Warn("failed to publish failure notification", append([]any{"error", notifyErr}, logArgs...)...)
		}
		return
	}

	// === Post-API phase ===
	phase = phasePostAPI

	summary, body := ParseSummary(analysis)

	title := hooks.NotifyTitle(alert)
	// Use the normalized SeverityLevel (not the raw alert.Severity label) so
	// that non-standard severity values map to the correct ntfy priority.
	// alert.Severity holds the raw label from the webhook and may not match
	// the priority-map keys; SeverityLevel is always one of the four
	// normalized enum values.
	priority := alert.SeverityLevel.NtfyPriority()

	if stormMode && deps.StormNotify != nil {
		deps.StormNotify.Add(name)
	} else if pubErr := PublishAll(ctx, deps.Publishers, title, priority, body); pubErr != nil {
		slog.Error("failed to publish analysis", append([]any{"error", pubErr}, logArgs...)...)
		deps.Metrics.RecordNtfyPublishError()
		// Phase is already phasePostAPI — defer keeps cooldowns. RecordFailed
		// is the operator-visible signal.
		deps.Metrics.RecordFailed()
		return
	}

	deps.Metrics.RecordProcessed(alert.SeverityLevel)
	if deps.History != nil && summary != "" {
		deps.History.RecordAnalysis(ctx, alert.Fingerprint, alert.SeverityLevel, RedactSecrets(summary))
	}
	slog.Info("analysis complete", logArgs...)
}
