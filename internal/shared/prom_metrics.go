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
	WebhooksTotal         *prometheus.CounterVec // labels: outcome
	AlertsEnqueued        prometheus.Counter
	AlertsDropped         *prometheus.CounterVec // labels: reason
	AlertsResolved        prometheus.Counter
	AlertsProcessed       *prometheus.CounterVec // labels: severity
	AlertsFailed          prometheus.Counter
	ProcessingDuration    prometheus.Histogram
	ContextGatherDuration prometheus.Histogram
	QueueWaitDuration     prometheus.Histogram
	QueueDepth            prometheus.Gauge

	// Claude API
	ClaudeAPIDuration prometheus.Histogram
	ClaudeAPIErrors   prometheus.Counter
	ClaudeAPIRetries  prometheus.Counter
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

	// Alert history
	HistoryEvents     *prometheus.CounterVec // labels: kind
	HistoryDrops      prometheus.Counter
	HistoryErrors     *prometheus.CounterVec // labels: op
	HistoryLookups    *prometheus.CounterVec // labels: result (hit|miss)
	HistoryRecurrence prometheus.Histogram
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

	pm.ContextGatherDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:        "alert_analyzer_context_gather_duration_seconds",
		Help:        "Time spent in GatherContext (static prefetch) before the Claude API call.",
		ConstLabels: constLabels,
		Buckets:     []float64{0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
	})

	pm.QueueWaitDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:        "alert_analyzer_queue_wait_duration_seconds",
		Help:        "Time an alert spends in the work queue before processing begins.",
		ConstLabels: constLabels,
		Buckets:     []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30},
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

	pm.ClaudeAPIRetries = prometheus.NewCounter(prometheus.CounterOpts{
		Name:        "alert_analyzer_claude_api_retries_total",
		Help:        "Claude API request attempts that were SDK-level retries (detected via X-Stainless-Retry-Count).",
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

	pm.HistoryEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "alert_analyzer_history_events_total",
		Help:        "Alert-history rows written, by kind (fire|analysis).",
		ConstLabels: constLabels,
	}, []string{"kind"})

	pm.HistoryDrops = prometheus.NewCounter(prometheus.CounterOpts{
		Name:        "alert_analyzer_history_drops_total",
		Help:        "History writes dropped because the write channel was full.",
		ConstLabels: constLabels,
	})

	pm.HistoryErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "alert_analyzer_history_store_errors_total",
		Help:        "History store errors, by operation (record|lookup|prune).",
		ConstLabels: constLabels,
	}, []string{"op"})

	pm.HistoryLookups = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "alert_analyzer_history_lookups_total",
		Help:        "History lookups by result: hit when recurrence context was found (count>1), miss when the fingerprint is new.",
		ConstLabels: constLabels,
	}, []string{"result"})

	pm.HistoryRecurrence = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:        "alert_analyzer_history_recurrence",
		Help:        "Fire count for a fingerprint at the moment recurrence context was injected.",
		ConstLabels: constLabels,
		Buckets:     []float64{2, 3, 4, 5, 7, 10, 15, 25, 50},
	})

	reg.MustRegister(
		pm.WebhooksTotal, pm.AlertsEnqueued, pm.AlertsDropped, pm.AlertsResolved,
		pm.AlertsProcessed, pm.AlertsFailed, pm.ProcessingDuration, pm.ContextGatherDuration, pm.QueueWaitDuration, pm.QueueDepth,
		pm.ClaudeAPIDuration, pm.ClaudeAPIErrors, pm.ClaudeAPIRetries, pm.ClaudeTokens,
		pm.AgentToolCalls, pm.AgentToolDuration, pm.AgentRoundsPerRun, pm.AgentRoundsExhausted,
		pm.StormModeActive, pm.ClaudeCircuitBreakerState, pm.NotifyAggregatorDrops,
		pm.NtfyPublishErrors,
		pm.HistoryEvents, pm.HistoryDrops, pm.HistoryErrors, pm.HistoryLookups, pm.HistoryRecurrence,
	)

	// Runtime/process collectors with the product ConstLabel applied via wrapper.
	wrapped := prometheus.WrapRegistererWith(constLabels, reg)
	wrapped.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	// Materialize the time series for bounded label combinations so dashboard
	// queries like rate(alert_analyzer_webhooks_total[5m]) return 0 instead
	// of "no data" before the first event arrives. CounterVec / HistogramVec
	// are lazy: a series only exists after the first WithLabelValues(...) call.
	for _, outcome := range []WebhookOutcome{
		WebhookAccepted, WebhookAuthFailed, WebhookPayloadInvalid,
		WebhookPayloadTooLarge, WebhookUnavailable, WebhookInternalError,
	} {
		pm.WebhooksTotal.WithLabelValues(string(outcome))
	}
	for _, reason := range []DropReason{
		DropReasonInvalidFingerprint, DropReasonCooldown,
		DropReasonGroupCooldown, DropReasonQueueFull,
		DropReasonOversizedAlert,
	} {
		pm.AlertsDropped.WithLabelValues(string(reason))
	}
	for _, sev := range allSeverities {
		pm.AlertsProcessed.WithLabelValues(sev.String())
	}
	for _, agg := range []string{"storm", "breaker"} {
		pm.NotifyAggregatorDrops.WithLabelValues(agg)
	}
	// Agent tool labels: pre-materialize the union of tool names across both
	// products. Unused names stay at 0 — small cardinality, harmless.
	for _, tool := range allAgentTools {
		for _, outcome := range allAgentOutcomes {
			pm.AgentToolCalls.WithLabelValues(tool, outcome)
		}
		pm.AgentToolDuration.WithLabelValues(tool)
	}

	for _, kind := range []string{"fire", "analysis"} {
		pm.HistoryEvents.WithLabelValues(kind)
	}
	for _, op := range []string{"record", "lookup", "prune"} {
		pm.HistoryErrors.WithLabelValues(op)
	}
	for _, result := range []string{"hit", "miss"} {
		pm.HistoryLookups.WithLabelValues(result)
	}

	return pm, nil
}

// allSeverities is the closed set of Severity values the registry uses for
// pre-materialization. Keep in sync with severity.go.
var allSeverities = []Severity{SeverityUnknown, SeverityInfo, SeverityWarning, SeverityCritical}

// allAgentTools is the union of agent tool names across k8s (kubectl_exec,
// promql_query) and checkmk (execute_command). Pre-materialized on every
// product registry; unused names just stay at 0.
var allAgentTools = []string{"kubectl_exec", "promql_query", "execute_command"}

// allAgentOutcomes is the closed set of outcome label values produced by the
// agent loops in both products. See internal/k8s/agent.go and
// internal/checkmk/agent.go for the emission sites.
// ssh_error is checkmk-only (SSH transport failure distinct from nonzero_exit).
var allAgentOutcomes = []string{
	"ok", "exec_error", "rejected_validation", "rejected_verb",
	"nonzero_exit", "ssh_error", "timeout",
}

// allTokenKinds is the closed set of kind label values for ClaudeTokens.
var allTokenKinds = []string{"input", "output", "cache_creation", "cache_read"}

// MaterializeClaudeTokensForModels pre-materializes the
// alert_analyzer_claude_tokens_total series for every (kind, severity, model)
// combination so dashboard queries return 0 instead of "no data" before the
// first Claude call. The model label is config-driven, so callers must pass
// the configured model set (typically AnalysisPolicy.AllModels()) — the
// registry constructor cannot know the values up front.
//
// Safe to call multiple times; WithLabelValues is idempotent.
func (p *PrometheusMetrics) MaterializeClaudeTokensForModels(models []string) {
	if p == nil || p.ClaudeTokens == nil {
		return
	}
	for _, sev := range allSeverities {
		for _, model := range models {
			if model == "" {
				continue
			}
			for _, kind := range allTokenKinds {
				p.ClaudeTokens.WithLabelValues(kind, sev.String(), model)
			}
		}
	}
}

// Registry returns the underlying prometheus.Registry for promhttp.HandlerFor.
func (p *PrometheusMetrics) Registry() *prometheus.Registry {
	return p.registry
}
