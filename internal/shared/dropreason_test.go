package shared

import "testing"

func TestDropReason_StringValues(t *testing.T) {
	cases := []struct {
		got  DropReason
		want string
	}{
		{DropReasonInvalidFingerprint, "invalid_fingerprint"},
		{DropReasonCooldown, "cooldown"},
		{DropReasonGroupCooldown, "group_cooldown"},
		{DropReasonQueueFull, "queue_full"},
	}
	for _, c := range cases {
		if string(c.got) != c.want {
			t.Errorf("DropReason %q -> %q, want %q", c.got, string(c.got), c.want)
		}
	}
}
