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

func TestCooldown_ExpiredEntriesEvictedWithinSweepBudget(t *testing.T) {
	cd := NewCooldownManager()
	ttl := time.Millisecond

	// Insert maxSweepPerCall-1 entries — all fit within a single sweep pass.
	n := maxSweepPerCall - 1
	for i := 0; i < n; i++ {
		cd.CheckAndSet(fmt.Sprintf("fp-%d", i), ttl)
	}
	time.Sleep(5 * time.Millisecond) // let all entries expire

	cd.CheckAndSet("trigger", ttl)

	cd.fpMu.Lock()
	remaining := len(cd.fpEntries)
	cd.fpMu.Unlock()

	// All n expired entries fit within the sweep cap, so only "trigger" remains.
	if remaining != 1 {
		t.Errorf("expected 1 entry after eviction within sweep budget, got %d", remaining)
	}
}

// TestCooldown_SweepBudgetBounded verifies that checkAndSetLocked examines at
// most maxSweepPerCall entries per call. With 2×maxSweepPerCall expired entries
// in the map, a single call must not sweep all of them — some must remain until
// subsequent calls, bounding the per-call latency under storm conditions.
func TestCooldown_SweepBudgetBounded(t *testing.T) {
	entries := make(map[string]cooldownEntry)
	ttl := time.Millisecond
	t0 := time.Now()

	const n = 2 * maxSweepPerCall
	for i := 0; i < n; i++ {
		entries[fmt.Sprintf("fp-%d", i)] = cooldownEntry{setAt: t0, ttl: ttl}
	}

	// Advance time past the TTL so all n entries are expired.
	now := t0.Add(10 * time.Millisecond)
	checkAndSetLocked(entries, "trigger", 5*time.Second, now)

	// With the cap, at most maxSweepPerCall entries are swept per call.
	// n - maxSweepPerCall expired entries + "trigger" must remain.
	if len(entries) == 1 {
		t.Errorf("all %d entries swept in a single call; sweep cap of %d was not enforced", n, maxSweepPerCall)
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
	if !cm.CheckAndSetWithGroup("fp1", time.Second, "g1", time.Second).Accepted() {
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

	if cm.CheckAndSetWithGroup("fp1", time.Second, "g1", time.Hour).Accepted() {
		t.Fatal("combined call should fail when group blocks")
	}
	if !cm.CheckAndSet("fp1", time.Second) {
		t.Fatal("fingerprint should NOT have been set when group blocked")
	}
}

func TestCooldownManager_CheckAndSetWithGroup_FPBlocksRollbackGroup(t *testing.T) {
	cm := NewCooldownManager()
	cm.CheckAndSet("fp1", time.Hour)

	if cm.CheckAndSetWithGroup("fp1", time.Second, "g1", time.Hour).Accepted() {
		t.Fatal("combined call should fail when fingerprint blocks")
	}
	if !cm.CheckAndSetGroup("g1", time.Second) {
		t.Fatal("group should NOT have been set when fingerprint blocked")
	}
}

func TestCooldownManager_CheckAndSetWithGroup_EmptyGroupSkipsGroup(t *testing.T) {
	cm := NewCooldownManager()
	if !cm.CheckAndSetWithGroup("fp1", time.Second, "", time.Second).Accepted() {
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
			if cm.CheckAndSetWithGroup(fmt.Sprintf("fp-%d", i), time.Second, "shared-group", time.Second).Accepted() {
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

func TestCheckAndSetWithGroup_Outcomes(t *testing.T) {
	cm := NewCooldownManager()
	ttl := 5 * time.Second

	t.Run("cold path returns Accepted", func(t *testing.T) {
		if got := cm.CheckAndSetWithGroup("fp1", ttl, "g1", ttl); got != CooldownAccepted {
			t.Errorf("got %v, want CooldownAccepted", got)
		}
	})

	t.Run("fingerprint already set returns Fingerprint", func(t *testing.T) {
		_ = cm.CheckAndSetWithGroup("fp2", ttl, "g2", ttl)
		if got := cm.CheckAndSetWithGroup("fp2", ttl, "g2-other", ttl); got != CooldownFingerprint {
			t.Errorf("got %v, want CooldownFingerprint", got)
		}
	})

	t.Run("group already set returns Group with fp rollback", func(t *testing.T) {
		_ = cm.CheckAndSetWithGroup("fp3", ttl, "g3", ttl)
		// fp3-other has not been set, but group g3 is. Outcome must be Group.
		if got := cm.CheckAndSetWithGroup("fp3-other", ttl, "g3", ttl); got != CooldownGroup {
			t.Errorf("got %v, want CooldownGroup", got)
		}
		// Verify the fingerprint entry was NOT set (rollback) by re-checking it
		// against a fresh group key.
		if got := cm.CheckAndSetWithGroup("fp3-other", ttl, "g3-fresh", ttl); got != CooldownAccepted {
			t.Errorf("fp3-other should be available after group-rejected, got %v", got)
		}
	})

	t.Run("groupKey empty never returns Group", func(t *testing.T) {
		_ = cm.CheckAndSetWithGroup("fp4", ttl, "", 0)
		if got := cm.CheckAndSetWithGroup("fp4", ttl, "", 0); got != CooldownFingerprint {
			t.Errorf("got %v, want CooldownFingerprint", got)
		}
	})

	t.Run("Accepted helper", func(t *testing.T) {
		if !CooldownAccepted.Accepted() {
			t.Error("CooldownAccepted.Accepted() must be true")
		}
		if CooldownFingerprint.Accepted() {
			t.Error("CooldownFingerprint.Accepted() must be false")
		}
		if CooldownGroup.Accepted() {
			t.Error("CooldownGroup.Accepted() must be false")
		}
	})
}

// TestCooldownManager_CheckAndSetWithGroup_ZeroGroupTTLSkipsGroup verifies
// that a non-empty groupKey combined with groupTTL=0 skips the group gate
// entirely — the same as when groupKey is empty. This is the real production
// path for the disabled-default (GROUP_COOLDOWN_SECONDS=0): pipelines always
// compute a non-empty group key, but the zero TTL must bypass the group check.
// Without this test a mutation of the || to && would silently change the
// disabled-feature path without triggering any test failure.
func TestCooldownManager_CheckAndSetWithGroup_ZeroGroupTTLSkipsGroup(t *testing.T) {
	cm := NewCooldownManager()
	ttl := 5 * time.Second
	const groupKey = "alertname:MyAlert"

	// Non-empty groupKey with groupTTL=0 must be accepted (group skipped).
	if got := cm.CheckAndSetWithGroup("fp1", ttl, groupKey, 0); got != CooldownAccepted {
		t.Fatalf("expected CooldownAccepted, got %v", got)
	}

	// The group map must be empty — no entry was written for the group.
	if !cm.CheckAndSetGroup(groupKey, ttl) {
		t.Fatal("group map should be empty; group key must not have been set")
	}

	// The fingerprint must now be in cooldown.
	if got := cm.CheckAndSetWithGroup("fp1", ttl, groupKey, 0); got != CooldownFingerprint {
		t.Errorf("expected CooldownFingerprint on second call, got %v", got)
	}
}

// TestCheckAndSetLocked_SweepAtExactBoundary verifies that the sweep condition
// (>= ttl) and the check condition (< ttl) are consistent: an entry at exactly
// its TTL boundary is treated as expired by the check AND swept during the same
// call. Before the fix (which used > instead of >=), entries at exactly elapsed
// == ttl were not swept and lingered as ghost entries until elapsed exceeded ttl.
func TestCheckAndSetLocked_SweepAtExactBoundary(t *testing.T) {
	entries := make(map[string]cooldownEntry)
	ttl := 5 * time.Second
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	// Insert two entries at T=0.
	if !checkAndSetLocked(entries, "a", ttl, t0) {
		t.Fatal("first set of 'a' should succeed")
	}
	if !checkAndSetLocked(entries, "b", ttl, t0) {
		t.Fatal("first set of 'b' should succeed")
	}

	// At T=exactly ttl, call for "b". Both entries are at elapsed==ttl.
	// With >= sweep: "a" is deleted and "b" is overwritten.
	// With old > sweep: "a" is NOT deleted — it lingers as a ghost entry.
	tExact := t0.Add(ttl)
	if !checkAndSetLocked(entries, "b", ttl, tExact) {
		t.Error("at exact TTL boundary, entry should be treated as expired and allow set")
	}

	// "a" should have been swept (elapsed == ttl → expired).
	if _, ok := entries["a"]; ok {
		t.Error("entry 'a' at exact TTL boundary should have been swept; got ghost entry")
	}

	// "b" should have been refreshed to tExact.
	if got := entries["b"].setAt; !got.Equal(tExact) {
		t.Errorf("entry 'b' setAt should be tExact=%v, got %v", tExact, got)
	}
}
