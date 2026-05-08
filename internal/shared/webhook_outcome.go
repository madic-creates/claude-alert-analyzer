package shared

import "net/http"

// WebhookOutcome classifies the HTTP outcome of a /webhook request. Recorded
// once per request after the final HTTP status is decided. Used as the per-call
// label on alert_analyzer_webhooks_total.
type WebhookOutcome string

const (
	WebhookAccepted        WebhookOutcome = "accepted"
	WebhookAuthFailed      WebhookOutcome = "auth_failed"
	WebhookPayloadInvalid  WebhookOutcome = "payload_invalid"
	WebhookPayloadTooLarge WebhookOutcome = "payload_too_large"
	WebhookUnavailable     WebhookOutcome = "unavailable"
	WebhookInternalError   WebhookOutcome = "internal_error"
)

// OutcomeForStatus maps an HTTP status code to a WebhookOutcome.
// Used by handlers to record alert_analyzer_webhooks_total once per request.
func OutcomeForStatus(s int) WebhookOutcome {
	switch s {
	case http.StatusOK, http.StatusAccepted:
		return WebhookAccepted
	case http.StatusUnauthorized:
		return WebhookAuthFailed
	case http.StatusBadRequest:
		return WebhookPayloadInvalid
	case http.StatusRequestEntityTooLarge:
		return WebhookPayloadTooLarge
	case http.StatusServiceUnavailable:
		return WebhookUnavailable
	default:
		return WebhookInternalError
	}
}
