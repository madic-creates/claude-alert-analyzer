package shared

import "testing"

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
