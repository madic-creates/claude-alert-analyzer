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
	// ClaudeAPIDuration is a histogram of Claude API call latency in seconds.
	ClaudeAPIDuration prometheus.Histogram
	// ClaudeAPIErrors counts Claude API errors, labeled by source.
	ClaudeAPIErrors *prometheus.CounterVec
	// NtfyPublishErrors counts ntfy publish failures, labeled by source.
	NtfyPublishErrors *prometheus.CounterVec
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

	claudeAPIDuration := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "claude_api_duration_seconds",
		Help:    "Latency of Claude API calls in seconds.",
		Buckets: claudeAPIBuckets,
	})

	claudeAPIErrors := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "claude_api_errors_total",
		Help: "Total number of Claude API errors, by source.",
	}, []string{"source"})

	ntfyPublishErrors := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ntfy_publish_errors_total",
		Help: "Total number of ntfy publish failures, by source.",
	}, []string{"source"})

	reg.MustRegister(
		alertsAnalyzed,
		alertsCooldown,
		queueDepth,
		claudeAPIDuration,
		claudeAPIErrors,
		ntfyPublishErrors,
	)

	return &PrometheusMetrics{
		registry:          reg,
		AlertsAnalyzed:    alertsAnalyzed,
		AlertsCooldown:    alertsCooldown,
		QueueDepth:        queueDepth,
		ClaudeAPIDuration: claudeAPIDuration,
		ClaudeAPIErrors:   claudeAPIErrors,
		NtfyPublishErrors: ntfyPublishErrors,
	}
}

// Registry returns the underlying prometheus.Registry for use with promhttp.HandlerFor.
func (p *PrometheusMetrics) Registry() *prometheus.Registry {
	return p.registry
}
