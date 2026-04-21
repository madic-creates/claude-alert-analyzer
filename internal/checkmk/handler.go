package checkmk

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
)

// maxWebhookBodyBytes is the upper limit for incoming webhook payloads.
// CheckMK notifications are single-service events; 1 MiB is generous.
const maxWebhookBodyBytes = 1 << 20 // 1 MiB

// HandleWebhook returns an HTTP handler that receives CheckMK webhook payloads,
// validates auth, applies cooldown, and enqueues alerts for processing.
// metrics may be nil, in which case no counters are incremented by the handler.
func HandleWebhook(cfg Config, cooldown *shared.CooldownManager, enqueue func(shared.AlertPayload) bool, metrics *shared.AlertMetrics) http.HandlerFunc {
	cooldownTTL := time.Duration(cfg.CooldownSeconds) * time.Second

	return func(w http.ResponseWriter, r *http.Request) {
		expected := []byte("Bearer " + cfg.WebhookSecret)
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), expected) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxWebhookBodyBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		var notif CheckMKNotification
		if err := json.Unmarshal(body, &notif); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
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
				cooldown.Clear(fingerprint(notif.Hostname, notif.ServiceDescription, "FLAPPING START", state))
				cooldown.Clear(fingerprint(notif.Hostname, notif.ServiceDescription, "FLAPPING STOP", state))
				cooldown.Clear(fingerprint(notif.Hostname, notif.ServiceDescription, "ACKNOWLEDGEMENT", state))
				cooldown.Clear(fingerprint(notif.Hostname, notif.ServiceDescription, "DOWNTIME START", state))
				cooldown.Clear(fingerprint(notif.Hostname, notif.ServiceDescription, "DOWNTIME END", state))
			}
			slog.Info("skipping recovery, cleared alert cooldowns",
				"hostname", notif.Hostname, "service", notif.ServiceDescription)
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "skipped recovery")
			return
		}

		fp := fingerprint(notif.Hostname, notif.ServiceDescription, notif.NotificationType, notif.ServiceState)

		if !cooldown.CheckAndSet(fp, cooldownTTL) {
			slog.Info("in cooldown", "hostname", notif.Hostname, "service", notif.ServiceDescription)
			if metrics != nil {
				metrics.AlertsCooldown.Add(1)
				metrics.RecordCooldown("checkmk")
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "in cooldown")
			return
		}

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
			Fingerprint: fp,
			Title:       title,
			Severity:    severity,
			Source:      "checkmk",
			Fields: map[string]string{
				"hostname":            notif.Hostname,
				"host_address":        notif.HostAddress,
				"service_description": notif.ServiceDescription,
				"service_state":       notif.ServiceState,
				"service_output":      notif.ServiceOutput,
				"host_state":          notif.HostState,
				"notification_type":   notif.NotificationType,
				"perf_data":           notif.PerfData,
				"long_plugin_output":  notif.LongPluginOutput,
				"timestamp":           notif.Timestamp,
			},
		}

		if enqueue(ap) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "queued")
		} else {
			slog.Warn("queue full", "hostname", notif.Hostname)
			cooldown.Clear(fp)
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, "queue full")
		}
	}
}

func fingerprint(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
