package shared

import (
	"testing"
	"time"
)

func TestCooldown_FirstCall_Allowed(t *testing.T) {
	cd := NewCooldownManager()
	if !cd.CheckAndSet("fp1", 5*time.Second) {
		t.Error("first call should be allowed")
	}
}

func TestCooldown_SecondCall_Blocked(t *testing.T) {
	cd := NewCooldownManager()
	cd.CheckAndSet("fp1", 5*time.Second)
	if cd.CheckAndSet("fp1", 5*time.Second) {
		t.Error("second call within TTL should be blocked")
	}
}

func TestCooldown_DifferentFingerprint_Allowed(t *testing.T) {
	cd := NewCooldownManager()
	cd.CheckAndSet("fp1", 5*time.Second)
	if !cd.CheckAndSet("fp2", 5*time.Second) {
		t.Error("different fingerprint should be allowed")
	}
}

func TestCooldown_Clear(t *testing.T) {
	cd := NewCooldownManager()
	cd.CheckAndSet("fp1", 5*time.Second)
	cd.Clear("fp1")
	if !cd.CheckAndSet("fp1", 5*time.Second) {
		t.Error("cleared fingerprint should be allowed again")
	}
}
