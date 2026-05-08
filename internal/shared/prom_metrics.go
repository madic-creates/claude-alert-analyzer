package shared

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// PrometheusMetrics holds all Prometheus instruments for a single analyzer
// binary. Construct via NewPrometheusMetrics(product); the product is applied
// as a ConstLabel on every metric (and on go_*/process_* via WrapRegistererWith).
type PrometheusMetrics struct {
	registry *prometheus.Registry

	// Pipeline
	WebhooksTotal      *prometheus.CounterVec // labels: outcome
	AlertsEnqueued     prometheus.Counter
	AlertsDropped      *prometheus.CounterVec // labels: reason
	AlertsResolved     prometheus.Counter
	AlertsProcessed    *prometheus.CounterVec // labels: severity
	AlertsFailed       prometheus.Counter
	ProcessingDuration prometheus.Histogram
	QueueDepth         prometheus.Gauge

	// Claude API
	ClaudeAPIDuration prometheus.Histogram
	ClaudeAPIErrors   prometheus.Counter
	ClaudeTokens      *prometheus.CounterVec // labels: kind, severity, model

	// Agent tool loop
	AgentToolCalls       *prometheus.CounterVec   // labels: tool, outcome
	AgentToolDuration    *prometheus.HistogramVec // labels: tool
	AgentRoundsPerRun    prometheus.Histogram
	AgentRoundsExhausted prometheus.Counter

	// Storm robustness
	StormModeActive           prometheus.Gauge
	ClaudeCircuitBreakerState prometheus.Gauge
	NotifyAggregatorDrops     *prometheus.CounterVec // labels: aggregator

	// External I/O
	NtfyPublishErrors prometheus.Counter
}

// NewPrometheusMetrics constructs the registry, applies the product ConstLabel,
// and registers all metrics including go_*/process_* collectors.
func NewPrometheusMetrics(product Product) (*PrometheusMetrics, error) {
	if !product.Valid() {
		return nil, fmt.Errorf("invalid product %q (must be %q or %q)",
			product, ProductK8s, ProductCheckMK)
	}
	reg := prometheus.NewRegistry()
	constLabels := prometheus.Labels{"product": string(product)}

	pm := &PrometheusMetrics{registry: reg}

	pm.WebhooksTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "alert_analyzer_webhooks_total",
		Help:        "Total /webhook HTTP requests by outcome.",
		ConstLabels: constLabels,
	}, []string{"outcome"})

	pm.AlertsEnqueued = prometheus.NewCounter(prometheus.CounterOpts{
		Name:        "alert_analyzer_alerts_enqueued_total",
		Help:        "Alerts successfully placed on the work queue.",
		ConstLabels: constLabels,
	})

	pm.AlertsDropped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "alert_analyzer_alerts_dropped_total",
		Help:        "Alerts dropped before reaching the work queue, by reason.",
		ConstLabels: constLabels,
	}, []string{"reason"})

	pm.AlertsResolved = prometheus.NewCounter(prometheus.CounterOpts{
		Name:        "alert_analyzer_alerts_resolved_total",
		Help:        "Alerts skipped because they were resolved (k8s) or recovery (CheckMK).",
		ConstLabels: constLabels,
	})

	pm.AlertsProcessed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "alert_analyzer_alerts_processed_total",
		Help:        "Alerts successfully analyzed and published, by severity.",
		ConstLabels: constLabels,
	}, []string{"severity"})

	pm.AlertsFailed = prometheus.NewCounter(prometheus.CounterOpts{
		Name:        "alert_analyzer_alerts_failed_total",
		Help:        "Alerts where analysis or publishing failed.",
		ConstLabels: constLabels,
	})

	pm.ProcessingDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:        "alert_analyzer_processing_duration_seconds",
		Help:        "End-to-end per-alert processing time.",
		ConstLabels: constLabels,
		Buckets:     []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 30, 45, 60, 90, 120, 300},
	})

	pm.QueueDepth = prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "alert_analyzer_queue_depth",
		Help:        "Current alerts waiting in the work queue.",
		ConstLabels: constLabels,
	})

	claudeAPIBuckets := []float64{1, 5, 10, 20, 30, 45, 60, 90, 120}
	pm.ClaudeAPIDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:        "alert_analyzer_claude_api_duration_seconds",
		Help:        "Latency of Claude API calls in seconds.",
		ConstLabels: constLabels,
		Buckets:     claudeAPIBuckets,
	})

	pm.ClaudeAPIErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name:        "alert_analyzer_claude_api_errors_total",
		Help:        "Total Claude API errors.",
		ConstLabels: constLabels,
	})

	pm.ClaudeTokens = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "alert_analyzer_claude_tokens_total",
		Help:        "Cumulative Claude API tokens, by kind/severity/model. Use sum by(kind) for cost analysis.",
		ConstLabels: constLabels,
	}, []string{"kind", "severity", "model"})

	pm.AgentToolCalls = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "alert_analyzer_agent_tool_calls_total",
		Help:        "Tool calls inside the agentic Claude loop, by tool and outcome.",
		ConstLabels: constLabels,
	}, []string{"tool", "outcome"})

	agentToolBuckets := []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
	pm.AgentToolDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:        "alert_analyzer_agent_tool_duration_seconds",
		Help:        "Per-tool wall-clock latency in seconds.",
		ConstLabels: constLabels,
		Buckets:     agentToolBuckets,
	}, []string{"tool"})

	pm.AgentRoundsPerRun = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:        "alert_analyzer_agent_rounds_per_run",
		Help:        "Tool rounds Claude used per completed agentic loop.",
		ConstLabels: constLabels,
		Buckets:     []float64{1, 2, 3, 4, 5, 7, 10, 15, 25, 45, 50},
	})

	pm.AgentRoundsExhausted = prometheus.NewCounter(prometheus.CounterOpts{
		Name:        "alert_analyzer_agent_rounds_exhausted_total",
		Help:        "Agentic loops that ended via forced summary (maxRounds reached).",
		ConstLabels: constLabels,
	})

	pm.StormModeActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "alert_analyzer_storm_mode_active",
		Help:        "1 when the storm-mode threshold is exceeded, 0 otherwise.",
		ConstLabels: constLabels,
	})

	pm.ClaudeCircuitBreakerState = prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "alert_analyzer_claude_circuit_breaker_state",
		Help:        "Circuit-breaker state: 0=closed, 1=open, 2=half-open.",
		ConstLabels: constLabels,
	})

	pm.NotifyAggregatorDrops = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "alert_analyzer_notify_aggregator_drops_total",
		Help:        "Alerts dropped by NotifyAggregator, by aggregator type.",
		ConstLabels: constLabels,
	}, []string{"aggregator"})

	pm.NtfyPublishErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name:        "alert_analyzer_ntfy_publish_errors_total",
		Help:        "Total ntfy publish failures.",
		ConstLabels: constLabels,
	})

	reg.MustRegister(
		pm.WebhooksTotal, pm.AlertsEnqueued, pm.AlertsDropped, pm.AlertsResolved,
		pm.AlertsProcessed, pm.AlertsFailed, pm.ProcessingDuration, pm.QueueDepth,
		pm.ClaudeAPIDuration, pm.ClaudeAPIErrors, pm.ClaudeTokens,
		pm.AgentToolCalls, pm.AgentToolDuration, pm.AgentRoundsPerRun, pm.AgentRoundsExhausted,
		pm.StormModeActive, pm.ClaudeCircuitBreakerState, pm.NotifyAggregatorDrops,
		pm.NtfyPublishErrors,
	)

	// Runtime/process collectors with the product ConstLabel applied via wrapper.
	wrapped := prometheus.WrapRegistererWith(constLabels, reg)
	wrapped.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	// Materialize the time series for bounded label combinations so dashboard
	// queries like rate(alert_analyzer_webhooks_total[5m]) return 0 instead
	// of "no data" before the first event arrives. CounterVec is lazy: a
	// series only exists after the first WithLabelValues(...) call.
	for _, outcome := range []WebhookOutcome{
		WebhookAccepted, WebhookAuthFailed, WebhookPayloadInvalid,
		WebhookPayloadTooLarge, WebhookUnavailable, WebhookInternalError,
	} {
		pm.WebhooksTotal.WithLabelValues(string(outcome))
	}
	for _, reason := range []DropReason{
		DropReasonInvalidFingerprint, DropReasonCooldown,
		DropReasonGroupCooldown, DropReasonQueueFull,
	} {
		pm.AlertsDropped.WithLabelValues(string(reason))
	}
	for _, sev := range []Severity{SeverityUnknown, SeverityInfo, SeverityWarning, SeverityCritical} {
		pm.AlertsProcessed.WithLabelValues(sev.String())
	}
	for _, agg := range []string{"storm", "breaker"} {
		pm.NotifyAggregatorDrops.WithLabelValues(agg)
	}

	return pm, nil
}

// Registry returns the underlying prometheus.Registry for promhttp.HandlerFor.
func (p *PrometheusMetrics) Registry() *prometheus.Registry {
	return p.registry
}
