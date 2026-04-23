package k8s

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
)

// PipelineDeps holds all dependencies for alert processing.
type PipelineDeps struct {
	Analyzer      shared.Analyzer
	Publishers    []shared.Publisher
	Cooldown      *shared.CooldownManager
	Metrics       *shared.AlertMetrics
	SystemPrompt  string
	GatherContext func(ctx context.Context, alert shared.AlertPayload) shared.AnalysisContext
}

// ProcessAlert gathers context, analyzes via Claude, and publishes results.
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
	alertname := alert.Title
	namespace := alert.Fields["label:namespace"]
	slog.Info("processing alert", "alertname", alertname, "namespace", namespace)

	actx := deps.GatherContext(ctx, alert)
	userPrompt := fmt.Sprintf("## Alert: %s\n- Status: %s\n- Severity: %s\n- Namespace: %s\n- StartsAt: %s\n\n%s",
		alertname, alert.Fields["status"], alert.Severity, namespace, alert.Fields["startsAt"], actx.FormatForPrompt())

	analysis, err := deps.Analyzer.Analyze(ctx, deps.SystemPrompt, userPrompt)
	if err != nil {
		slog.Error("analysis failed", "alertname", alertname, "error", err)
		deps.Metrics.RecordClaudeAPIError(alert.Source)
		if notifyErr := shared.PublishAll(ctx, deps.Publishers,
			fmt.Sprintf("Analysis FAILED: %s", alertname), "5",
			fmt.Sprintf("**Analysis failed** for %s: %v\n\nManual investigation needed.", alertname, err)); notifyErr != nil {
			slog.Warn("failed to publish failure notification", "alertname", alertname, "error", notifyErr)
		}
		deps.Cooldown.Clear(alert.Fingerprint)
		deps.Metrics.AlertsFailed.Add(1)
		return
	}
	if analysis == "" {
		slog.Warn("analysis returned empty result, treating as failure", "alertname", alertname)
		if notifyErr := shared.PublishAll(ctx, deps.Publishers,
			fmt.Sprintf("Analysis FAILED: %s", alertname), "5",
			fmt.Sprintf("**Analysis produced empty result** for %s.\n\nManual investigation needed.", alertname)); notifyErr != nil {
			slog.Warn("failed to publish failure notification", "alertname", alertname, "error", notifyErr)
		}
		deps.Cooldown.Clear(alert.Fingerprint)
		deps.Metrics.AlertsFailed.Add(1)
		return
	}

	title := fmt.Sprintf("Analysis: %s", alertname)
	if namespace != "" {
		title = fmt.Sprintf("Analysis: %s (%s)", alertname, namespace)
	}

	priorityMap := map[string]string{"critical": "5", "warning": "4", "info": "2"}
	priority := priorityMap[alert.Severity]
	if priority == "" {
		priority = "3"
	}

	if err := shared.PublishAll(ctx, deps.Publishers, title, priority, analysis); err != nil {
		deps.Metrics.RecordNtfyPublishError(alert.Source)
		deps.Cooldown.Clear(alert.Fingerprint)
		deps.Metrics.AlertsFailed.Add(1)
		return
	}

	deps.Metrics.AlertsProcessed.Add(1)
	deps.Metrics.RecordAnalyzed(alert.Source, alert.Severity)
	slog.Info("analysis complete", "alertname", alertname)
}
