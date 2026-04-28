package shared

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// AlertMetrics holds operational counters for an alert analyzer instance.
// All fields are safe for concurrent use via sync/atomic.
//
// Prom contains the labeled Prometheus metrics (alerts_analyzed_total,
// alerts_cooldown_total, queue_depth, claude_api_duration_seconds,
// claude_api_errors_total, ntfy_publish_errors_total). It is nil-safe: all
// recording helpers below check for nil before accessing it so that tests
// that only instantiate AlertMetrics with `new(AlertMetrics)` continue to
// work without wiring up a PrometheusMetrics.
type AlertMetrics struct {
	// WebhooksReceived counts every authenticated POST /webhook request.
	WebhooksReceived atomic.Int64
	// AlertsQueued counts alerts successfully placed on the work queue.
	AlertsQueued atomic.Int64
	// AlertsQueueFull counts alerts dropped because the work queue was at capacity.
	AlertsQueueFull atomic.Int64
	// AlertsCooldown counts alerts skipped because a duplicate is already in cooldown.
	AlertsCooldown atomic.Int64
	// AlertsProcessed counts alerts that were fully analyzed and published.
	AlertsProcessed atomic.Int64
	// AlertsFailed counts alerts where analysis or publishing failed.
	AlertsFailed atomic.Int64
	// ProcessingDurationSum tracks total processing time in microseconds.
	ProcessingDurationSum atomic.Int64
	// ProcessingDurationCount tracks total alerts processed (for avg calculation).
	ProcessingDurationCount atomic.Int64
	// AlertsInvalidFingerprint counts alerts dropped because their fingerprint
	// was empty or exceeded maxFingerprintLen. These are silently skipped by the
	// k8s webhook handler; this counter makes them visible to operators.
	AlertsInvalidFingerprint atomic.Int64

	// Prom holds the labeled Prometheus metrics. May be nil for tests.
	Prom *PrometheusMetrics
}

// RecordAnalyzed increments the alerts_analyzed_total counter for the given
// source and severity. No-ops when Prom is nil.
func (m *AlertMetrics) RecordAnalyzed(source, severity string) {
	if m.Prom != nil {
		m.Prom.AlertsAnalyzed.WithLabelValues(source, severity).Inc()
	}
}

// RecordCooldown increments the alerts_cooldown_total counter for the given
// source. No-ops when Prom is nil.
func (m *AlertMetrics) RecordCooldown(source string) {
	if m.Prom != nil {
		m.Prom.AlertsCooldown.WithLabelValues(source).Inc()
	}
}

// SetQueueDepth sets the queue_depth gauge for the given source. No-ops when
// Prom is nil.
func (m *AlertMetrics) SetQueueDepth(source string, depth float64) {
	if m.Prom != nil {
		m.Prom.QueueDepth.WithLabelValues(source).Set(depth)
	}
}

// RecordClaudeAPIError increments the claude_api_errors_total counter for the
// given source. No-ops when Prom is nil.
func (m *AlertMetrics) RecordClaudeAPIError(source string) {
	if m.Prom != nil {
		m.Prom.ClaudeAPIErrors.WithLabelValues(source).Inc()
	}
}

// RecordNtfyPublishError increments the ntfy_publish_errors_total counter for
// the given source. No-ops when Prom is nil.
func (m *AlertMetrics) RecordNtfyPublishError(source string) {
	if m.Prom != nil {
		m.Prom.NtfyPublishErrors.WithLabelValues(source).Inc()
	}
}

// MetricsHandler returns an HTTP handler that renders all counters in
// Prometheus text exposition format (version 0.0.4).
//
// The response consists of two sections:
//  1. Hand-rolled atomic counters (existing operational metrics without labels).
//  2. If Prom is non-nil, the labeled Prometheus metrics gathered from its
//     private registry via promhttp.
//
// All atomic counters are read into a strings.Builder before any bytes are
// written to the ResponseWriter. This produces a single write to the
// underlying TCP connection rather than one syscall per metric line, and
// ensures the response body is assembled consistently before transmission.
func (m *AlertMetrics) MetricsHandler() http.HandlerFunc {
	// Create the promhttp handler once at registration time rather than on
	// every scrape request. promhttp.HandlerFor is safe to call concurrently
	// after construction, so this is both correct and more efficient.
	var promHandler http.Handler
	if m.Prom != nil {
		promHandler = promhttp.HandlerFor(m.Prom.Registry(), promhttp.HandlerOpts{})
	}
	return m.metricsHandlerWith(promHandler)
}

// metricsHandlerWith is the testable core of MetricsHandler. It accepts an
// optional promHandler so tests can inject a fake handler that returns a
// non-200 status without needing a real Prometheus registry.
func (m *AlertMetrics) metricsHandlerWith(promHandler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var b strings.Builder
		fmt.Fprintf(&b, "# HELP alert_analyzer_webhooks_received_total Total webhook requests received.\n")
		fmt.Fprintf(&b, "# TYPE alert_analyzer_webhooks_received_total counter\n")
		fmt.Fprintf(&b, "alert_analyzer_webhooks_received_total %d\n", m.WebhooksReceived.Load())
		fmt.Fprintf(&b, "# HELP alert_analyzer_alerts_queued_total Alerts successfully enqueued for processing.\n")
		fmt.Fprintf(&b, "# TYPE alert_analyzer_alerts_queued_total counter\n")
		fmt.Fprintf(&b, "alert_analyzer_alerts_queued_total %d\n", m.AlertsQueued.Load())
		fmt.Fprintf(&b, "# HELP alert_analyzer_alerts_queue_full_total Alerts dropped because the work queue was full.\n")
		fmt.Fprintf(&b, "# TYPE alert_analyzer_alerts_queue_full_total counter\n")
		fmt.Fprintf(&b, "alert_analyzer_alerts_queue_full_total %d\n", m.AlertsQueueFull.Load())
		fmt.Fprintf(&b, "# HELP alert_analyzer_alerts_cooldown_total Alerts skipped because a duplicate is in cooldown.\n")
		fmt.Fprintf(&b, "# TYPE alert_analyzer_alerts_cooldown_total counter\n")
		fmt.Fprintf(&b, "alert_analyzer_alerts_cooldown_total %d\n", m.AlertsCooldown.Load())
		fmt.Fprintf(&b, "# HELP alert_analyzer_alerts_processed_total Alerts successfully analyzed and published.\n")
		fmt.Fprintf(&b, "# TYPE alert_analyzer_alerts_processed_total counter\n")
		fmt.Fprintf(&b, "alert_analyzer_alerts_processed_total %d\n", m.AlertsProcessed.Load())
		fmt.Fprintf(&b, "# HELP alert_analyzer_alerts_failed_total Alerts where analysis or publishing failed.\n")
		fmt.Fprintf(&b, "# TYPE alert_analyzer_alerts_failed_total counter\n")
		fmt.Fprintf(&b, "alert_analyzer_alerts_failed_total %d\n", m.AlertsFailed.Load())
		fmt.Fprintf(&b, "# HELP alert_analyzer_alerts_invalid_fingerprint_total Alerts dropped due to empty or oversized fingerprint.\n")
		fmt.Fprintf(&b, "# TYPE alert_analyzer_alerts_invalid_fingerprint_total counter\n")
		fmt.Fprintf(&b, "alert_analyzer_alerts_invalid_fingerprint_total %d\n", m.AlertsInvalidFingerprint.Load())
		fmt.Fprintf(&b, "# HELP alert_analyzer_processing_duration_seconds Processing time per alert.\n")
		fmt.Fprintf(&b, "# TYPE alert_analyzer_processing_duration_seconds summary\n")
		fmt.Fprintf(&b, "alert_analyzer_processing_duration_seconds_sum %f\n", float64(m.ProcessingDurationSum.Load())/1e6)
		fmt.Fprintf(&b, "alert_analyzer_processing_duration_seconds_count %d\n", m.ProcessingDurationCount.Load())

		// Append labeled Prometheus metrics when available. Only include the
		// output if promhttp signalled success: a non-200 WriteHeader call means
		// promhttp encountered a gather error and wrote an HTTP error body rather
		// than valid Prometheus text. Appending that error body would corrupt the
		// exposition format and cause scrapers to reject the entire response.
		// bw.code is 0 when promhttp never calls WriteHeader (the normal success
		// path), and http.StatusOK (200) when it explicitly confirms success.
		if promHandler != nil {
			var promBuf bytes.Buffer
			bw := newBufferedResponseWriter(&promBuf)
			promHandler.ServeHTTP(bw, r)
			if bw.code == 0 || bw.code == http.StatusOK {
				b.Write(promBuf.Bytes())
			}
		}

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprint(w, b.String())
	}
}

// bufferedResponseWriter captures the response body written by promhttp into a
// bytes.Buffer so it can be concatenated with the hand-rolled metrics output.
type bufferedResponseWriter struct {
	buf    *bytes.Buffer
	header http.Header
	code   int
}

func newBufferedResponseWriter(buf *bytes.Buffer) *bufferedResponseWriter {
	return &bufferedResponseWriter{buf: buf, header: make(http.Header)}
}

func (w *bufferedResponseWriter) Header() http.Header         { return w.header }
func (w *bufferedResponseWriter) WriteHeader(code int)        { w.code = code }
func (w *bufferedResponseWriter) Write(b []byte) (int, error) { return w.buf.Write(b) }
