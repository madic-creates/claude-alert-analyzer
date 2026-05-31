package shared

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// AlertMetrics is a nil-safe façade over PrometheusMetrics. All methods on a
// nil receiver or with a nil Prom field are no-ops, which lets test code
// construct AlertMetrics with NewAlertMetrics(nil) when it does not care
// about counter values.
type AlertMetrics struct {
	Prom *PrometheusMetrics
}

// NewAlertMetrics returns a façade over the given PrometheusMetrics. Pass
// nil for tests that don't need real counters.
func NewAlertMetrics(prom *PrometheusMetrics) *AlertMetrics {
	return &AlertMetrics{Prom: prom}
}

// Pipeline counters

func (m *AlertMetrics) RecordWebhookOutcome(outcome WebhookOutcome) {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.WebhooksTotal.WithLabelValues(string(outcome)).Inc()
}

func (m *AlertMetrics) RecordEnqueued() {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.AlertsEnqueued.Inc()
}

func (m *AlertMetrics) RecordDropped(reason DropReason) {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.AlertsDropped.WithLabelValues(string(reason)).Inc()
}

func (m *AlertMetrics) RecordResolved() {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.AlertsResolved.Inc()
}

func (m *AlertMetrics) RecordProcessed(severity Severity) {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.AlertsProcessed.WithLabelValues(severity.String()).Inc()
}

func (m *AlertMetrics) RecordFailed() {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.AlertsFailed.Inc()
}

func (m *AlertMetrics) ObserveProcessingDuration(d time.Duration) {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.ProcessingDuration.Observe(d.Seconds())
}

func (m *AlertMetrics) SetQueueDepth(depth float64) {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.QueueDepth.Set(depth)
}

// Claude API

func (m *AlertMetrics) ObserveClaudeAPIDuration(d time.Duration) {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.ClaudeAPIDuration.Observe(d.Seconds())
}

func (m *AlertMetrics) RecordClaudeAPIError() {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.ClaudeAPIErrors.Inc()
}

// RecordClaudeUsage increments the alert_analyzer_claude_tokens_total counter
// once per kind (input/output/cache_creation/cache_read), keyed by severity
// and model.
func (m *AlertMetrics) RecordClaudeUsage(severity Severity, model string,
	in, out, cacheCreation, cacheRead int) {
	if m == nil || m.Prom == nil {
		return
	}
	sev := severity.String()
	m.Prom.ClaudeTokens.With(prometheus.Labels{"kind": "input", "severity": sev, "model": model}).Add(float64(in))
	m.Prom.ClaudeTokens.With(prometheus.Labels{"kind": "output", "severity": sev, "model": model}).Add(float64(out))
	m.Prom.ClaudeTokens.With(prometheus.Labels{"kind": "cache_creation", "severity": sev, "model": model}).Add(float64(cacheCreation))
	m.Prom.ClaudeTokens.With(prometheus.Labels{"kind": "cache_read", "severity": sev, "model": model}).Add(float64(cacheRead))
}

// Agent tool loop

func (m *AlertMetrics) RecordAgentToolCall(tool, outcome string, duration time.Duration) {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.AgentToolCalls.WithLabelValues(tool, outcome).Inc()
	m.Prom.AgentToolDuration.WithLabelValues(tool).Observe(duration.Seconds())
}

func (m *AlertMetrics) RecordAgentRounds(rounds int, exhausted bool) {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.AgentRoundsPerRun.Observe(float64(rounds))
	if exhausted {
		m.Prom.AgentRoundsExhausted.Inc()
	}
}

// Storm robustness

func (m *AlertMetrics) SetStormMode(active bool) {
	if m == nil || m.Prom == nil {
		return
	}
	v := 0.0
	if active {
		v = 1
	}
	m.Prom.StormModeActive.Set(v)
}

func (m *AlertMetrics) SetBreakerState(state int) {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.ClaudeCircuitBreakerState.Set(float64(state))
}

// AggregatorDropsCounter returns the labeled counter for the given aggregator
// kind ("storm" | "breaker"). Returns nil when Prom is nil.
func (m *AlertMetrics) AggregatorDropsCounter(kind string) prometheus.Counter {
	if m == nil || m.Prom == nil {
		return nil
	}
	return m.Prom.NotifyAggregatorDrops.WithLabelValues(kind)
}

// External I/O

func (m *AlertMetrics) RecordNtfyPublishError() {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.NtfyPublishErrors.Inc()
}

// Alert history

func (m *AlertMetrics) RecordHistoryEvent(kind string) {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.HistoryEvents.WithLabelValues(kind).Inc()
}

func (m *AlertMetrics) RecordHistoryDrop() {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.HistoryDrops.Inc()
}

func (m *AlertMetrics) RecordHistoryError(op string) {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.HistoryErrors.WithLabelValues(op).Inc()
}

func (m *AlertMetrics) ObserveRecurrence(n int) {
	if m == nil || m.Prom == nil {
		return
	}
	m.Prom.HistoryRecurrence.Observe(float64(n))
}
