package shared

import (
	"net/http"
	"testing"
)

func TestWebhookOutcome_StringValues(t *testing.T) {
	cases := []struct {
		got  WebhookOutcome
		want string
	}{
		{WebhookAccepted, "accepted"},
		{WebhookAuthFailed, "auth_failed"},
		{WebhookPayloadInvalid, "payload_invalid"},
		{WebhookPayloadTooLarge, "payload_too_large"},
		{WebhookUnavailable, "unavailable"},
		{WebhookInternalError, "internal_error"},
	}
	for _, c := range cases {
		if string(c.got) != c.want {
			t.Errorf("WebhookOutcome %q -> %q, want %q", c.got, string(c.got), c.want)
		}
	}
}

func TestOutcomeForStatus(t *testing.T) {
	cases := []struct {
		status int
		want   WebhookOutcome
	}{
		{http.StatusOK, WebhookAccepted},
		{http.StatusAccepted, WebhookAccepted},
		{http.StatusUnauthorized, WebhookAuthFailed},
		{http.StatusBadRequest, WebhookPayloadInvalid},
		{http.StatusRequestEntityTooLarge, WebhookPayloadTooLarge},
		{http.StatusServiceUnavailable, WebhookUnavailable},
		// Unknown status codes fall through to WebhookInternalError.
		{http.StatusInternalServerError, WebhookInternalError},
		{http.StatusNotFound, WebhookInternalError},
		{http.StatusForbidden, WebhookInternalError},
	}
	for _, c := range cases {
		got := OutcomeForStatus(c.status)
		if got != c.want {
			t.Errorf("OutcomeForStatus(%d) = %q, want %q", c.status, got, c.want)
		}
	}
}
