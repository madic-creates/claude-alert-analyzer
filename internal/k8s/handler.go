package k8s

import (
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
// Alertmanager batches multiple alerts per request; 1 MiB is generous.
const maxWebhookBodyBytes = 1 << 20 // 1 MiB

// HandleWebhook returns an HTTP handler that receives Alertmanager webhook payloads,
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

		var payload AlertmanagerWebhook
		if err := json.Unmarshal(body, &payload); err != nil {
			http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
			return
		}

		queued := 0
		dropped := 0
		for _, alert := range payload.Alerts {
			if cfg.SkipResolved && alert.Status == "resolved" {
				// Clear the cooldown so that if the same alert fires again within
				// the TTL window it is not silently suppressed.
				cooldown.Clear(alert.Fingerprint)
				slog.Info("skipping resolved, cleared cooldown", "alertname", alert.Labels["alertname"])
				continue
			}

			if !cooldown.CheckAndSet(alert.Fingerprint, cooldownTTL) {
				slog.Info("in cooldown", "alertname", alert.Labels["alertname"])
				if metrics != nil {
					metrics.AlertsCooldown.Add(1)
				}
				continue
			}

			ap := shared.AlertPayload{
				Fingerprint: alert.Fingerprint,
				Title:       alert.Labels["alertname"],
				Severity:    alert.Labels["severity"],
				Source:      "k8s",
				Fields:      make(map[string]string),
			}
			// Copy all labels and annotations into Fields
			for k, v := range alert.Labels {
				ap.Fields["label:"+k] = v
			}
			for k, v := range alert.Annotations {
				ap.Fields["annotation:"+k] = v
			}
			ap.Fields["status"] = alert.Status
			ap.Fields["startsAt"] = alert.StartsAt.Format("2006-01-02T15:04:05Z07:00")

			if enqueue(ap) {
				queued++
			} else {
				slog.Warn("work queue full, rejecting", "alertname", alert.Labels["alertname"])
				cooldown.Clear(alert.Fingerprint)
				dropped++
			}
		}

		if dropped > 0 {
			// 503 triggers Alertmanager retry
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, "queued %d, dropped %d (queue full)", queued, dropped)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "queued %d alerts", queued)
	}
}
