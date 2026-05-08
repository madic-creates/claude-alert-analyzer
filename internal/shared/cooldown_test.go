package shared

import (
	"fmt"
	"sync"
	"sync/atomic"
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

	cd.fpMu.Lock()
	remaining := len(cd.fpEntries)
	cd.fpMu.Unlock()

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

// TestCooldown_LongTTLEntryNotEvictedByShortTTLSweep is a regression test for
// the bug where CheckAndSet used the current call's TTL to sweep ALL entries.
// An entry stored with a 10-second TTL must not be evicted when a concurrent
// call with a 1-millisecond TTL runs the sweep.
func TestCooldown_LongTTLEntryNotEvictedByShortTTLSweep(t *testing.T) {
	cd := NewCooldownManager()

	// Store fp-long with a generous 10-second TTL — it should stay alive.
	if !cd.CheckAndSet("fp-long", 10*time.Second) {
		t.Fatal("first CheckAndSet for fp-long should return true")
	}

	// Now call CheckAndSet with a very short TTL (1ms) for a different key.
	// With the old (buggy) code this sweep would delete fp-long because
	// now.Sub(fp-long.setAt) > 1ms is true almost immediately.
	time.Sleep(5 * time.Millisecond) // ensure 1ms TTL of fp-short would have expired
	cd.CheckAndSet("fp-short", time.Millisecond)

	// fp-long must still be in cooldown — it was stored with a 10-second TTL.
	if cd.CheckAndSet("fp-long", 10*time.Second) {
		t.Error("fp-long was incorrectly evicted by the short-TTL sweep; it should still be in cooldown")
	}
}

func TestCooldownManager_CheckAndSetGroup_FirstAndRepeat(t *testing.T) {
	cm := NewCooldownManager()
	if !cm.CheckAndSetGroup("g1", time.Second) {
		t.Fatal("first call should set")
	}
	if cm.CheckAndSetGroup("g1", time.Second) {
		t.Fatal("second call should be blocked")
	}
}

func TestCooldownManager_ClearGroup(t *testing.T) {
	cm := NewCooldownManager()
	cm.CheckAndSetGroup("g1", time.Hour)
	cm.ClearGroup("g1")
	if !cm.CheckAndSetGroup("g1", time.Second) {
		t.Fatal("after Clear, set should succeed again")
	}
}

func TestCooldownManager_CheckAndSetWithGroup_BothEmpty(t *testing.T) {
	cm := NewCooldownManager()
	if !cm.CheckAndSetWithGroup("fp1", time.Second, "g1", time.Second) {
		t.Fatal("first combined call should set both")
	}
	if cm.CheckAndSet("fp1", time.Second) {
		t.Fatal("fingerprint should be blocked after combined set")
	}
	if cm.CheckAndSetGroup("g1", time.Second) {
		t.Fatal("group should be blocked after combined set")
	}
}

func TestCooldownManager_CheckAndSetWithGroup_GroupBlocksRollbackFP(t *testing.T) {
	cm := NewCooldownManager()
	cm.CheckAndSetGroup("g1", time.Hour)

	if cm.CheckAndSetWithGroup("fp1", time.Second, "g1", time.Hour) {
		t.Fatal("combined call should fail when group blocks")
	}
	if !cm.CheckAndSet("fp1", time.Second) {
		t.Fatal("fingerprint should NOT have been set when group blocked")
	}
}

func TestCooldownManager_CheckAndSetWithGroup_FPBlocksRollbackGroup(t *testing.T) {
	cm := NewCooldownManager()
	cm.CheckAndSet("fp1", time.Hour)

	if cm.CheckAndSetWithGroup("fp1", time.Second, "g1", time.Hour) {
		t.Fatal("combined call should fail when fingerprint blocks")
	}
	if !cm.CheckAndSetGroup("g1", time.Second) {
		t.Fatal("group should NOT have been set when fingerprint blocked")
	}
}

func TestCooldownManager_CheckAndSetWithGroup_EmptyGroupSkipsGroup(t *testing.T) {
	cm := NewCooldownManager()
	if !cm.CheckAndSetWithGroup("fp1", time.Second, "", time.Second) {
		t.Fatal("empty group should not block fingerprint set")
	}
	if cm.CheckAndSet("fp1", time.Second) {
		t.Fatal("fingerprint should now be set")
	}
	if !cm.CheckAndSetGroup("any", time.Second) {
		t.Fatal("group map should be empty")
	}
}

func TestCooldownManager_CheckAndSetWithGroup_ConcurrentAtomic(t *testing.T) {
	cm := NewCooldownManager()
	const N = 50
	var ok int64
	var fail int64
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			if cm.CheckAndSetWithGroup(fmt.Sprintf("fp-%d", i), time.Second, "shared-group", time.Second) {
				atomic.AddInt64(&ok, 1)
			} else {
				atomic.AddInt64(&fail, 1)
			}
		}(i)
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("expected exactly 1 winner, got %d (rest=%d)", ok, fail)
	}
	if fail != N-1 {
		t.Fatalf("expected %d losers, got %d", N-1, fail)
	}
}
