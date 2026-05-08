package shared

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
