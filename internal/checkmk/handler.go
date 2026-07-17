package checkmk

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
)

// maxWebhookBodyBytes is the upper limit for incoming webhook payloads.
// CheckMK notifications are single-service events; 1 MiB is generous.
const maxWebhookBodyBytes = 1 << 20 // 1 MiB

// maxFreeTextFieldBytes caps the single-line free-text notification fields
// (service_output, perf_data) at ingest. They are rendered into the Claude
// prompt without any other length bound, so an oversized value would inflate
// API cost for the whole analysis. Truncated with a marker, not rejected.
const maxFreeTextFieldBytes = 4 << 10 // 4 KiB

// maxLongOutputBytes caps long_plugin_output at ingest. The prompt renderer
// truncates it further (4 KiB); this larger cap bounds queue memory.
const maxLongOutputBytes = 16 << 10 // 16 KiB

// HandleWebhook returns an HTTP handler that receives CheckMK webhook payloads,
// validates auth, applies cooldown, and enqueues alerts for processing.
// metrics may be nil, in which case no counters are incremented by the handler.
// storm may be nil (storm-mode disabled).
func HandleWebhook(
	cfg Config,
	cooldown *shared.CooldownManager,
	enqueue func(shared.AlertPayload) bool,
	metrics *shared.AlertMetrics,
	storm *shared.StormDetector,
	history shared.HistoryStore,
) http.HandlerFunc {
	cooldownTTL := time.Duration(cfg.CooldownSeconds) * time.Second
	expectedTokenHash := shared.WebhookTokenHash(cfg.WebhookSecret)

	return func(w http.ResponseWriter, r *http.Request) {
		httpStatus := http.StatusOK
		defer func() {
			metrics.RecordWebhookOutcome(shared.OutcomeForStatus(httpStatus))
		}()

		if status, ok := shared.CheckWebhookAuth(w, r, expectedTokenHash); !ok {
			httpStatus = status
			return
		}

		var notif CheckMKNotification
		if status, ok := shared.DecodeWebhookBody(w, r, maxWebhookBodyBytes, &notif); !ok {
			httpStatus = status
			return
		}

		if notif.NotificationType == "RECOVERY" {
			// Clear cooldown entries for all non-RECOVERY notification types so that
			// a service which recovers and then fails again within the TTL window is
			// not silently suppressed. Each notification type uses its own fingerprint
			// key, so we must clear all types that may have been queued. The empty
			// string covers host-level notifications where ServiceState is "".
			for _, state := range []string{"CRITICAL", "WARNING", "UNKNOWN", "OK", ""} {
				cooldown.Clear(fingerprint(notif.Hostname, notif.ServiceDescription, "PROBLEM", state))
				cooldown.Clear(fingerprint(notif.Hostname, notif.ServiceDescription, "FLAPPINGSTART", state))
				cooldown.Clear(fingerprint(notif.Hostname, notif.ServiceDescription, "FLAPPINGSTOP", state))
				cooldown.Clear(fingerprint(notif.Hostname, notif.ServiceDescription, "ACKNOWLEDGEMENT", state))
				cooldown.Clear(fingerprint(notif.Hostname, notif.ServiceDescription, "DOWNTIMESTART", state))
				cooldown.Clear(fingerprint(notif.Hostname, notif.ServiceDescription, "DOWNTIMEEND", state))
				cooldown.Clear(fingerprint(notif.Hostname, notif.ServiceDescription, "DOWNTIMECANCELLED", state))
				cooldown.Clear(fingerprint(notif.Hostname, notif.ServiceDescription, "CUSTOM", state))
			}
			cooldown.ClearGroup(groupKeyFromNotif(notif))
			slog.Info("skipping recovery, cleared alert cooldowns",
				"hostname", notif.Hostname, "service", notif.ServiceDescription)
			metrics.RecordResolved()
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "skipped recovery")
			return
		}

		fp := fingerprint(notif.Hostname, notif.ServiceDescription, notif.NotificationType, notif.ServiceState)
		groupKey := groupKeyFromNotif(notif)

		// Record the fire before the cooldown gate (counts suppressed + queue-full
		// fires). Best-effort, non-blocking.
		history.RecordFire(r.Context(), fp, shared.SeverityFromCheckMK(notif.ServiceState, notif.HostState))

		switch outcome := cooldown.CheckAndSetWithGroup(fp, cooldownTTL, groupKey, cfg.GroupCooldownTTL); outcome {
		case shared.CooldownAccepted:
			// proceed
		case shared.CooldownFingerprint:
			slog.Info("in cooldown (fingerprint)", "hostname", notif.Hostname, "service", notif.ServiceDescription, "groupKey", groupKey)
			metrics.RecordDropped(shared.DropReasonCooldown)
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "in cooldown")
			return
		case shared.CooldownGroup:
			slog.Info("in cooldown (group)", "hostname", notif.Hostname, "service", notif.ServiceDescription, "groupKey", groupKey)
			metrics.RecordDropped(shared.DropReasonGroupCooldown)
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "in cooldown")
			return
		}

		// Storm-mode counter: only counts alerts that pass the cooldown check.
		storm.Record() // nil-safe

		severity := "warning"
		switch notif.ServiceState {
		case "CRITICAL":
			severity = "critical"
		case "WARNING":
			severity = "warning"
		case "UNKNOWN":
			severity = "unknown"
		case "OK":
			severity = "ok"
		case "":
			// Host-level notification: ServiceState is empty, fall back to HostState.
			switch notif.HostState {
			case "DOWN", "UNREACHABLE":
				severity = "critical"
			case "UP":
				severity = "ok"
			}
		}

		title := notif.Hostname
		if notif.ServiceDescription != "" {
			title = fmt.Sprintf("%s - %s", notif.Hostname, notif.ServiceDescription)
		}

		ap := shared.AlertPayload{
			Fingerprint:   fp,
			Title:         title,
			Severity:      severity,
			SeverityLevel: shared.SeverityFromCheckMK(notif.ServiceState, notif.HostState),
			Source:        "checkmk",
			GroupKey:      groupKey,
			Fields: map[string]string{
				"hostname":            notif.Hostname,
				"host_address":        notif.HostAddress,
				"service_description": notif.ServiceDescription,
				"service_state":       notif.ServiceState,
				"service_output":      shared.Truncate(notif.ServiceOutput, maxFreeTextFieldBytes),
				"host_state":          notif.HostState,
				"notification_type":   notif.NotificationType,
				"perf_data":           shared.Truncate(notif.PerfData, maxFreeTextFieldBytes),
				"long_plugin_output":  shared.Truncate(notif.LongPluginOutput, maxLongOutputBytes),
				"timestamp":           notif.Timestamp,
			},
		}

		if enqueue(ap) {
			metrics.RecordEnqueued()
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "queued")
		} else {
			slog.Warn("queue full", "hostname", notif.Hostname, "service", notif.ServiceDescription)
			cooldown.Clear(fp)
			cooldown.ClearGroup(groupKey)
			metrics.RecordDropped(shared.DropReasonQueueFull)
			httpStatus = http.StatusServiceUnavailable
			w.WriteHeader(httpStatus)
			fmt.Fprint(w, "queue full")
		}
	}
}

// groupKeyFromNotif derives the group cooldown key from a CheckMK notification.
// Empty service description (host-level events) is replaced with the sentinel
// "_host_" so they don't collide with each other or with services that
// happen to have an empty description. Parts are length-prefixed because
// CheckMK ServiceDescriptions commonly contain ":" (e.g. "Disk: /var"); a
// plain "host:svc" join would let "h:Disk: /var" and "h:Disk:" + " /var"
// collide. Same length-prefix rationale as fingerprint() below.
func groupKeyFromNotif(n CheckMKNotification) string {
	svc := n.ServiceDescription
	if svc == "" {
		svc = "_host_"
	}
	return fmt.Sprintf("%d:%s%d:%s", len(n.Hostname), n.Hostname, len(svc), svc)
}

// fingerprint hashes the supplied parts using length-prefixed encoding so that
// no two distinct part sequences can produce the same SHA-256 input. A null-byte
// separator between parts is insufficient: fingerprint("a\x00","b") and
// fingerprint("a","\x00b") both yield the byte sequence a\x00\x00b\x00 when the
// null at the end of the first part merges with the separator. Length-prefixed
// encoding (e.g. "2:a\x001:b" vs "1:a2:\x00b") is unambiguous regardless of
// the byte content of each part.
func fingerprint(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		fmt.Fprintf(h, "%d:", len(p))
		h.Write([]byte(p))
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
