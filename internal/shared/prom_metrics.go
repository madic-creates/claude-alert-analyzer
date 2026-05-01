package shared

import (
	"github.com/prometheus/client_golang/prometheus"
)

// PrometheusMetrics holds the labeled Prometheus metrics exposed at /metrics.
// It uses a private registry so that Go process default metrics (go_*, process_*)
// are not included unless explicitly added.
type PrometheusMetrics struct {
	registry *prometheus.Registry

	// AlertsAnalyzed counts successfully analyzed alerts, labeled by source and severity.
	AlertsAnalyzed *prometheus.CounterVec
	// AlertsCooldown counts alerts skipped due to cooldown, labeled by source.
	AlertsCooldown *prometheus.CounterVec
	// QueueDepth is a gauge tracking the current number of alerts waiting in the work queue.
	QueueDepth *prometheus.GaugeVec
	// ClaudeAPIDuration is a histogram of Claude API call latency in seconds, labeled by source.
	ClaudeAPIDuration *prometheus.HistogramVec
	// ClaudeAPIErrors counts Claude API errors, labeled by source.
	ClaudeAPIErrors *prometheus.CounterVec
	// NtfyPublishErrors counts ntfy publish failures, labeled by source.
	NtfyPublishErrors *prometheus.CounterVec

	// AgentToolCalls counts every tool call made inside an agentic loop, labeled
	// by source ("k8s" / "checkmk"), tool name, and outcome
	// (ok / rejected_validation / rejected_verb / exec_error / nonzero_exit / timeout).
	AgentToolCalls *prometheus.CounterVec
	// AgentToolDuration is a histogram of per-tool wall-clock latency in seconds,
	// labeled by source and tool name.
	AgentToolDuration *prometheus.HistogramVec
	// AgentRoundsUsed observes how many tool rounds Claude actually used per
	// completed loop, labeled by source. Compare _count to AgentRoundsExhausted
	// to see how often Claude ended naturally vs. hit the cap.
	AgentRoundsUsed *prometheus.HistogramVec
	// AgentRoundsExhausted counts loops that returned via the forced-summary path
	// because maxRounds was reached, labeled by source.
	AgentRoundsExhausted *prometheus.CounterVec
}

// NewPrometheusMetrics creates and registers all labeled Prometheus metrics on a
// private registry. Call Registry() to obtain the registry for promhttp.HandlerFor.
func NewPrometheusMetrics() *PrometheusMetrics {
	reg := prometheus.NewRegistry()

	alertsAnalyzed := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "alerts_analyzed_total",
		Help: "Total number of alerts successfully analyzed, by source and severity.",
	}, []string{"source", "severity"})

	alertsCooldown := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "alerts_cooldown_total",
		Help: "Total number of alerts skipped because a duplicate is already in cooldown, by source.",
	}, []string{"source"})

	queueDepth := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "queue_depth",
		Help: "Current number of alerts waiting in the work queue, by source.",
	}, []string{"source"})

	// claudeAPIBuckets covers the expected latency range for Claude API calls.
	// The Anthropic API typically responds in 5–60 s for analysis requests and
	// up to 120 s for long agentic tool-loop conversations. prometheus.DefBuckets
	// top out at 10 s, which would place the vast majority of calls in the +Inf
	// bucket and make the histogram useless for percentile estimation.
	claudeAPIBuckets := []float64{1, 5, 10, 20, 30, 45, 60, 90, 120}

	claudeAPIDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "claude_api_duration_seconds",
		Help:    "Latency of Claude API calls in seconds, by source.",
		Buckets: claudeAPIBuckets,
	}, []string{"source"})

	claudeAPIErrors := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "claude_api_errors_total",
		Help: "Total number of Claude API errors, by source.",
	}, []string{"source"})

	ntfyPublishErrors := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ntfy_publish_errors_total",
		Help: "Total number of ntfy publish failures, by source.",
	}, []string{"source"})

	agentToolCalls := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "agent_tool_calls_total",
		Help: "Total number of tool calls made inside an agentic Claude loop, by source, tool, and outcome.",
	}, []string{"source", "tool", "outcome"})

	// agentToolBuckets cover the realistic per-tool wall-clock range.
	// kubectl/PromQL calls are typically 50 ms – 5 s; the 10 s ceiling is the
	// per-call timeout enforced by the handlers.
	agentToolBuckets := []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

	agentToolDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "agent_tool_duration_seconds",
		Help:    "Per-tool wall-clock latency in seconds for agentic-loop tool calls, by source and tool.",
		Buckets: agentToolBuckets,
	}, []string{"source", "tool"})

	agentRoundsUsed := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "agent_rounds_used",
		Help:    "Number of tool rounds Claude used per completed agentic loop, by source.",
		Buckets: []float64{1, 2, 3, 4, 5, 7, 10, 15, 25, 50},
	}, []string{"source"})

	agentRoundsExhausted := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "agent_rounds_exhausted_total",
		Help: "Number of agentic loops that ended via forced-summary because maxRounds was reached, by source.",
	}, []string{"source"})

	reg.MustRegister(
		alertsAnalyzed,
		alertsCooldown,
		queueDepth,
		claudeAPIDuration,
		claudeAPIErrors,
		ntfyPublishErrors,
		agentToolCalls,
		agentToolDuration,
		agentRoundsUsed,
		agentRoundsExhausted,
	)

	return &PrometheusMetrics{
		registry:             reg,
		AlertsAnalyzed:       alertsAnalyzed,
		AlertsCooldown:       alertsCooldown,
		QueueDepth:           queueDepth,
		ClaudeAPIDuration:    claudeAPIDuration,
		ClaudeAPIErrors:      claudeAPIErrors,
		NtfyPublishErrors:    ntfyPublishErrors,
		AgentToolCalls:       agentToolCalls,
		AgentToolDuration:    agentToolDuration,
		AgentRoundsUsed:      agentRoundsUsed,
		AgentRoundsExhausted: agentRoundsExhausted,
	}
}

// Registry returns the underlying prometheus.Registry for use with promhttp.HandlerFor.
func (p *PrometheusMetrics) Registry() *prometheus.Registry {
	return p.registry
}
