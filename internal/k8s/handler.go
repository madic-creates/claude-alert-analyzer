package k8s

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
// Alertmanager batches multiple alerts per request; 1 MiB is generous.
const maxWebhookBodyBytes = 1 << 20 // 1 MiB

// maxAlertsPerBatch is the maximum number of alert objects accepted in a
// single Alertmanager webhook payload. Alertmanager typically sends small
// batches; an unbounded array could cause excessive cooldown-map growth and
// CPU consumption even for an authenticated caller.
const maxAlertsPerBatch = 100

// maxFingerprintLen is the maximum byte length accepted for an alert
// fingerprint. Alertmanager generates 40-character hex fingerprints; we allow
// some extra room but cap at 256 bytes to prevent unbounded map key growth.
const maxFingerprintLen = 256

// maxFieldValueBytes caps a single label or annotation value. Long values
// (typically a verbose description annotation) are truncated with a marker
// rather than rejected, since a single long annotation is legitimate.
const maxFieldValueBytes = 4 << 10 // 4 KiB

// maxAlertFieldsBytes caps the aggregate byte size of one alert's labels and
// annotations (keys + values, values counted after per-value truncation).
// A label-flood alert would otherwise pass handler validation and only become
// a problem later: inflating queue memory and downstream processing cost.
// Real alerts carry a few KiB at most; 16 KiB is generous.
const maxAlertFieldsBytes = 16 << 10 // 16 KiB

// HandleWebhook returns an HTTP handler that receives Alertmanager webhook
// payloads. metrics may be nil. storm may be nil (storm-mode disabled).
func HandleWebhook(
	cfg Config,
	cooldown *shared.CooldownManager,
	enqueue func(shared.AlertPayload) bool,
	metrics *shared.AlertMetrics,
	storm *shared.StormDetector,
	history shared.HistoryStore,
) http.HandlerFunc {
	cooldownTTL := time.Duration(cfg.CooldownSeconds) * time.Second
	// Hash the expected token so the per-request comparison always operates on
	// equal-length (32-byte) inputs. subtle.ConstantTimeCompare returns 0
	// immediately when input lengths differ, which would otherwise let a remote
	// caller probe the secret length by varying the Authorization header length.
	expectedTokenHash := sha256.Sum256([]byte("Bearer " + cfg.WebhookSecret))

	return func(w http.ResponseWriter, r *http.Request) {
		httpStatus := http.StatusOK
		defer func() {
			metrics.RecordWebhookOutcome(shared.OutcomeForStatus(httpStatus))
		}()

		gotHash := sha256.Sum256([]byte(r.Header.Get("Authorization")))
		if subtle.ConstantTimeCompare(gotHash[:], expectedTokenHash[:]) != 1 {
			httpStatus = http.StatusUnauthorized
			http.Error(w, "unauthorized", httpStatus)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxWebhookBodyBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				httpStatus = http.StatusRequestEntityTooLarge
				http.Error(w, "request body too large", httpStatus)
				return
			}
			httpStatus = http.StatusBadRequest
			http.Error(w, "bad request", httpStatus)
			return
		}

		var payload AlertmanagerWebhook
		if err := json.Unmarshal(body, &payload); err != nil {
			httpStatus = http.StatusBadRequest
			http.Error(w, "invalid JSON", httpStatus)
			return
		}

		if len(payload.Alerts) > maxAlertsPerBatch {
			httpStatus = http.StatusRequestEntityTooLarge
			http.Error(w, "too many alerts in batch", httpStatus)
			return
		}

		queued := 0
		dropped := 0
		for _, alert := range payload.Alerts {
			if len(alert.Fingerprint) == 0 || len(alert.Fingerprint) > maxFingerprintLen {
				slog.Warn("skipping alert with invalid fingerprint", "alertname", alert.Labels["alertname"])
				metrics.RecordDropped(shared.DropReasonInvalidFingerprint)
				continue
			}

			// Aggregate size gate before any per-alert work. Values are counted
			// at their post-truncation size so one long description annotation
			// does not disqualify an otherwise normal alert; only a flood of
			// labels/annotations (or oversized keys) trips the cap.
			fieldsBytes := 0
			for _, m := range []map[string]string{alert.Labels, alert.Annotations} {
				for k, v := range m {
					fieldsBytes += len(k) + min(len(v), maxFieldValueBytes)
				}
			}
			if fieldsBytes > maxAlertFieldsBytes {
				slog.Warn("skipping oversized alert",
					"alertname", shared.SanitizeAlertField(shared.Truncate(alert.Labels["alertname"], 256)),
					"fieldsBytes", fieldsBytes)
				metrics.RecordDropped(shared.DropReasonOversizedAlert)
				continue
			}

			// Cap individual values in place so every downstream use — group
			// key, cooldown clearing, payload title, Fields — sees the same
			// bounded value.
			for _, m := range []map[string]string{alert.Labels, alert.Annotations} {
				for k, v := range m {
					if len(v) > maxFieldValueBytes {
						m[k] = shared.Truncate(v, maxFieldValueBytes)
					}
				}
			}

			if cfg.SkipResolved && alert.Status == "resolved" {
				// Clear both the fingerprint and group cooldowns so that if the
				// same alert (or another alert in the same alertname+namespace group)
				// fires again within the TTL window it is not silently suppressed.
				// Without clearing the group cooldown, a subsequent alert with a
				// different fingerprint but the same alertname+namespace would be
				// blocked by the lingering group entry even though the original alert
				// resolved.
				cooldown.Clear(alert.Fingerprint)
				cooldown.ClearGroup(groupKeyFromLabels(alert.Labels))
				slog.Info("skipping resolved, cleared cooldown", "alertname", alert.Labels["alertname"])
				metrics.RecordResolved()
				continue
			}

			// Record the fire before the cooldown gate so cooldown-suppressed and
			// queue-full fires are still counted. Best-effort (non-blocking).
			history.RecordFire(r.Context(), alert.Fingerprint, shared.SeverityFromAlertmanager(alert.Labels))

			groupKey := groupKeyFromLabels(alert.Labels)

			// Atomic combined check: either both cooldowns set, or neither.
			switch outcome := cooldown.CheckAndSetWithGroup(alert.Fingerprint, cooldownTTL, groupKey, cfg.GroupCooldownTTL); outcome {
			case shared.CooldownAccepted:
				// proceed
			case shared.CooldownFingerprint:
				slog.Info("in cooldown (fingerprint)", "alertname", alert.Labels["alertname"], "groupKey", groupKey)
				metrics.RecordDropped(shared.DropReasonCooldown)
				continue
			case shared.CooldownGroup:
				slog.Info("in cooldown (group)", "alertname", alert.Labels["alertname"], "groupKey", groupKey)
				metrics.RecordDropped(shared.DropReasonGroupCooldown)
				continue
			}

			// Storm-mode counter: only counts alerts that pass the cooldown check.
			storm.Record() // nil-safe

			ap := shared.AlertPayload{
				Fingerprint:   alert.Fingerprint,
				Title:         alert.Labels["alertname"],
				Severity:      alert.Labels["severity"],
				SeverityLevel: shared.SeverityFromAlertmanager(alert.Labels),
				Source:        "k8s",
				Fields:        make(map[string]string),
				GroupKey:      groupKey,
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
				metrics.RecordEnqueued()
				queued++
			} else {
				slog.Warn("work queue full, rejecting", "alertname", alert.Labels["alertname"])
				cooldown.Clear(alert.Fingerprint)
				cooldown.ClearGroup(groupKey)
				metrics.RecordDropped(shared.DropReasonQueueFull)
				dropped++
			}
		}

		if dropped > 0 {
			// 503 triggers Alertmanager retry
			httpStatus = http.StatusServiceUnavailable
			w.WriteHeader(httpStatus)
			fmt.Fprintf(w, "queued %d, dropped %d (queue full)", queued, dropped)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "queued %d alerts", queued)
	}
}

// groupKeyFromLabels derives the group cooldown key from Alertmanager labels.
// Empty namespace is replaced with the sentinel "_cluster_" so cluster-wide
// alerts (e.g. KubeAPIDown) don't collide with each other or with alerts
// that happen to have an empty Namespace label. Parts are length-prefixed so
// alertnames or namespaces containing ":" cannot collide with adjacent parts
// (same rationale as fingerprint() in the checkmk handler).
func groupKeyFromLabels(labels map[string]string) string {
	name := labels["alertname"]
	ns := labels["namespace"]
	if ns == "" {
		ns = "_cluster_"
	}
	return fmt.Sprintf("%d:%s%d:%s", len(name), name, len(ns), ns)
}
