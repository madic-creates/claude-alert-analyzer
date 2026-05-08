package shared

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestNewPrometheusMetrics_PrematerializedSeries verifies that bounded label
// combinations exist as zero-valued time series immediately after construction,
// so dashboard queries like rate(alert_analyzer_webhooks_total[5m]) return 0
// instead of "no data" before the first event arrives. CounterVec is lazy by
// default: a series only materializes on the first WithLabelValues(...) call.
func TestNewPrometheusMetrics_PrematerializedSeries(t *testing.T) {
	pm := NewPrometheusMetricsForTest(ProductK8s)

	cases := []struct {
		name string
		got  int
		want int
	}{
		{"WebhooksTotal (6 outcomes)", testutil.CollectAndCount(pm.WebhooksTotal), 6},
		{"AlertsDropped (4 reasons)", testutil.CollectAndCount(pm.AlertsDropped), 4},
		{"AlertsProcessed (4 severities)", testutil.CollectAndCount(pm.AlertsProcessed), 4},
		{"NotifyAggregatorDrops (2 aggregators)", testutil.CollectAndCount(pm.NotifyAggregatorDrops), 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.got != c.want {
				t.Errorf("series count = %d, want %d", c.got, c.want)
			}
		})
	}

	// Verify each WebhookOutcome value is materialized at zero
	for _, outcome := range []WebhookOutcome{
		WebhookAccepted, WebhookAuthFailed, WebhookPayloadInvalid,
		WebhookPayloadTooLarge, WebhookUnavailable, WebhookInternalError,
	} {
		v := testutil.ToFloat64(pm.WebhooksTotal.WithLabelValues(string(outcome)))
		if v != 0 {
			t.Errorf("WebhooksTotal[outcome=%q] = %v, want 0 (zero-materialized)", outcome, v)
		}
	}

	// Verify each DropReason value is materialized at zero
	for _, reason := range []DropReason{
		DropReasonInvalidFingerprint, DropReasonCooldown,
		DropReasonGroupCooldown, DropReasonQueueFull,
	} {
		v := testutil.ToFloat64(pm.AlertsDropped.WithLabelValues(string(reason)))
		if v != 0 {
			t.Errorf("AlertsDropped[reason=%q] = %v, want 0", reason, v)
		}
	}

	// Verify each Severity value is materialized at zero
	for _, sev := range []Severity{SeverityUnknown, SeverityInfo, SeverityWarning, SeverityCritical} {
		v := testutil.ToFloat64(pm.AlertsProcessed.WithLabelValues(sev.String()))
		if v != 0 {
			t.Errorf("AlertsProcessed[severity=%q] = %v, want 0", sev, v)
		}
	}
}
