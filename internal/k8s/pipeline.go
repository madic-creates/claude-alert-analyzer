package k8s

import (
	"context"
	"fmt"
	"time"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
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
	// History records fires/analyses and supplies recurrence context. In
	// production a non-nil store is wired in main; access here is nil-safe so
	// existing tests that omit it keep working.
	History shared.HistoryStore
	// HistoryInjectPrior gates the prior-analyses sub-block.
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

// pipelineHooks adapts the k8s-specific behavior to shared.ProcessAlert.
type pipelineHooks struct {
	deps PipelineDeps
}

// DisplayName sanitizes the alertname at the point of extraction so that all
// downstream uses — failure notification bodies, log fields, and the Claude
// prompt — are free of control characters from a crafted Alertmanager webhook.
func (pipelineHooks) DisplayName(alert shared.AlertPayload) string {
	return shared.SanitizeAlertField(alert.Title)
}

func (pipelineHooks) LogArgs(alert shared.AlertPayload) []any {
	return []any{
		"alertname", shared.SanitizeAlertField(alert.Title),
		"namespace", shared.SanitizeAlertField(alert.Fields["label:namespace"]),
	}
}

func (pipelineHooks) NotifyTitle(alert shared.AlertPayload) string {
	alertname := shared.SanitizeAlertField(alert.Title)
	if namespace := shared.SanitizeAlertField(alert.Fields["label:namespace"]); namespace != "" {
		return fmt.Sprintf("Analysis: %s (%s)", alertname, namespace)
	}
	return fmt.Sprintf("Analysis: %s", alertname)
}

func (h pipelineHooks) Prepare(ctx context.Context, alert shared.AlertPayload, inject func(shared.AnalysisContext) shared.AnalysisContext) shared.AnalyzeFunc {
	deps := h.deps
	alertname := shared.SanitizeAlertField(alert.Title)

	gatherStart := time.Now()
	actx := deps.GatherContext(ctx, alert)
	deps.Metrics.ObserveContextGatherDuration(time.Since(gatherStart))
	actx = inject(actx)

	userPrompt := fmt.Sprintf("## Alert: %s\n- Status: %s\n- Severity: %s\n- Namespace: %s\n- StartsAt: %s\n\n%s",
		alertname,
		shared.SanitizeAlertField(alert.Fields["status"]),
		shared.SanitizeAlertField(alert.Severity),
		shared.SanitizeAlertField(alert.Fields["label:namespace"]),
		shared.SanitizeAlertField(alert.Fields["startsAt"]),
		actx.FormatForPrompt())

	return func(ctx context.Context, model string, rounds int) (string, error) {
		if rounds == 0 {
			return deps.Analyzer.Analyze(ctx, alert.SeverityLevel, model, StaticAnalysisSystemPrompt, userPrompt)
		}
		return RunAgenticDiagnostics(ctx, deps.ToolRunner, deps.KubectlRunner, deps.Prom, deps.Metrics, alert.SeverityLevel, alertname, userPrompt, rounds, model)
	}
}

// ProcessAlert gathers context, analyzes via Claude, and publishes results.
// The orchestration (failure phases, breaker permits, cooldown cleanup, storm
// handling) lives in shared.ProcessAlert; this adapter supplies the
// k8s-specific hooks.
func ProcessAlert(ctx context.Context, deps PipelineDeps, alert shared.AlertPayload) {
	shared.ProcessAlert(ctx, deps.sharedDeps(), pipelineHooks{deps: deps}, alert)
}
