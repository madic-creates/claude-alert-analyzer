package shared

// DropReason classifies why an incoming alert was dropped before analysis.
// Used as a per-call label on alert_analyzer_alerts_dropped_total.
type DropReason string

const (
	DropReasonInvalidFingerprint DropReason = "invalid_fingerprint"
	DropReasonCooldown           DropReason = "cooldown"
	DropReasonGroupCooldown      DropReason = "group_cooldown"
	DropReasonQueueFull          DropReason = "queue_full"
)
