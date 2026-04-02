package checkmk

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
)

func HandleWebhook(cfg Config, cooldown *shared.CooldownManager, enqueue func(shared.AlertPayload) bool) http.HandlerFunc {
	cooldownTTL := time.Duration(cfg.CooldownSeconds) * time.Second

	return func(w http.ResponseWriter, r *http.Request) {
		expected := []byte("Bearer " + cfg.WebhookSecret)
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), expected) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		var notif CheckMKNotification
		if err := json.Unmarshal(body, &notif); err != nil {
			http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
			return
		}

		if notif.NotificationType == "RECOVERY" {
			slog.Info("skipping recovery", "hostname", notif.Hostname, "service", notif.ServiceDescription)
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "skipped recovery")
			return
		}

		fp := fingerprint(notif.Hostname, notif.ServiceDescription, notif.NotificationType, notif.ServiceState)

		if !cooldown.CheckAndSet(fp, cooldownTTL) {
			slog.Info("in cooldown", "hostname", notif.Hostname, "service", notif.ServiceDescription)
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
		}

		ap := shared.AlertPayload{
			Fingerprint: fp,
			Title:       fmt.Sprintf("%s - %s", notif.Hostname, notif.ServiceDescription),
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
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}
