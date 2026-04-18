package shared

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
)

// AlertMetrics holds operational counters for an alert analyzer instance.
// All fields are safe for concurrent use via sync/atomic.
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
}

// MetricsHandler returns an HTTP handler that renders all counters in
// Prometheus text exposition format (version 0.0.4).
//
// All atomic counters are read into a strings.Builder before any bytes are
// written to the ResponseWriter. This produces a single write to the
// underlying TCP connection rather than one syscall per metric line, and
// ensures the response body is assembled consistently before transmission.
func (m *AlertMetrics) MetricsHandler() http.HandlerFunc {
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
		fmt.Fprintf(&b, "# HELP alert_analyzer_processing_duration_seconds Processing time per alert.\n")
		fmt.Fprintf(&b, "# TYPE alert_analyzer_processing_duration_seconds summary\n")
		fmt.Fprintf(&b, "alert_analyzer_processing_duration_seconds_sum %f\n", float64(m.ProcessingDurationSum.Load())/1e6)
		fmt.Fprintf(&b, "alert_analyzer_processing_duration_seconds_count %d\n", m.ProcessingDurationCount.Load())
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprint(w, b.String())
	}
}
