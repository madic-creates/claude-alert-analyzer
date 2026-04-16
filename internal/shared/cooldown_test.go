package shared

import (
	"fmt"
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

func TestCooldown_ExpiredEntriesFullyEvicted(t *testing.T) {
	cd := NewCooldownManager()
	ttl := time.Millisecond

	// Insert 150 unique fingerprints with a tiny TTL.
	for i := 0; i < 150; i++ {
		cd.CheckAndSet(fmt.Sprintf("fp-%d", i), ttl)
	}
	time.Sleep(5 * time.Millisecond) // let all entries expire

	// A new call must trigger eviction of ALL 150 expired entries.
	cd.CheckAndSet("trigger", ttl)

	cd.mu.Lock()
	remaining := len(cd.entries)
	cd.mu.Unlock()

	// Only "trigger" should remain.
	if remaining != 1 {
		t.Errorf("expected 1 entry after full eviction, got %d", remaining)
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
