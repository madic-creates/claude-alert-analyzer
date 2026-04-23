package k8s

import (
	"strings"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
)

// AlertPayloadToAlert reconstructs a k8s Alert from a shared.AlertPayload.
// Fields with "label:" prefix are restored to Labels, "annotation:" prefix to
// Annotations, and the "status" key to Status. This is the inverse of the
// normalisation performed by HandleWebhook when it builds the AlertPayload.
func AlertPayloadToAlert(ap shared.AlertPayload) Alert {
	alert := Alert{
		Status:      ap.Fields["status"],
		Labels:      make(map[string]string),
		Annotations: make(map[string]string),
		Fingerprint: ap.Fingerprint,
	}
	for key, v := range ap.Fields {
		if strings.HasPrefix(key, "label:") {
			alert.Labels[strings.TrimPrefix(key, "label:")] = v
		} else if strings.HasPrefix(key, "annotation:") {
			alert.Annotations[strings.TrimPrefix(key, "annotation:")] = v
		}
	}
	return alert
}
