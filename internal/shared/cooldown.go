package shared

import (
	"sync"
	"time"
)

type cooldownEntry struct {
	setAt time.Time
	ttl   time.Duration
}

// CooldownManager owns two independent cooldown maps:
//
//   - fingerprint cooldown (existing): one entry per alert fingerprint
//   - group cooldown (Phase 2): coarser-grained dedup (e.g. alertname+namespace)
//
// Lock-Hierarchy: groupMu < fpMu. CheckAndSetWithGroup is the only method
// that holds both locks; it acquires them in groupMu → fpMu order to avoid
// deadlock.
type CooldownManager struct {
	fpMu      sync.Mutex
	fpEntries map[string]cooldownEntry

	groupMu      sync.Mutex
	groupEntries map[string]cooldownEntry
}

func NewCooldownManager() *CooldownManager {
	return &CooldownManager{
		fpEntries:    make(map[string]cooldownEntry),
		groupEntries: make(map[string]cooldownEntry),
	}
}

// CooldownOutcome describes which cooldown gate (if any) blocked an alert.
type CooldownOutcome int

const (
	// CooldownAccepted: both gates passed; the alert is allowed and entries are set.
	CooldownAccepted CooldownOutcome = iota
	// CooldownFingerprint: the fingerprint was already in cooldown.
	CooldownFingerprint
	// CooldownGroup: the group key was already in cooldown.
	CooldownGroup
)

// Accepted reports whether the alert passed all cooldown gates.
func (o CooldownOutcome) Accepted() bool { return o == CooldownAccepted }

// CheckAndSet returns true if the fingerprint was not in cooldown and is now set.
// Sweeps expired entries on every call to keep the map bounded.
func (cm *CooldownManager) CheckAndSet(fingerprint string, ttl time.Duration) bool {
	cm.fpMu.Lock()
	defer cm.fpMu.Unlock()
	return checkAndSetLocked(cm.fpEntries, fingerprint, ttl, time.Now())
}

// Clear removes a fingerprint entry.
func (cm *CooldownManager) Clear(fingerprint string) {
	cm.fpMu.Lock()
	delete(cm.fpEntries, fingerprint)
	cm.fpMu.Unlock()
}

// CheckAndSetGroup is the group-level analogue of CheckAndSet, with its own
// map and mutex (groupMu).
func (cm *CooldownManager) CheckAndSetGroup(groupKey string, ttl time.Duration) bool {
	cm.groupMu.Lock()
	defer cm.groupMu.Unlock()
	return checkAndSetLocked(cm.groupEntries, groupKey, ttl, time.Now())
}

// ClearGroup removes a group entry.
func (cm *CooldownManager) ClearGroup(groupKey string) {
	cm.groupMu.Lock()
	delete(cm.groupEntries, groupKey)
	cm.groupMu.Unlock()
}

// CheckAndSetWithGroup atomically checks both cooldowns and sets both, or
// neither, in fixed lock order (groupMu → fpMu). Returns CooldownAccepted on
// success, CooldownFingerprint or CooldownGroup on rejection; in the rejection
// cases nothing is mutated (the rollback semantics are preserved).
//
// groupKey == "" or groupTTL == 0 → group is skipped entirely; the call
// reduces to CheckAndSet on the fingerprint alone (with the same locking).
// In this mode the only possible non-Accepted return is CooldownFingerprint.
//
// Lock-Discipline: BOTH mutexes are held over the entire decision (not
// taken individually and released between steps). Order: groupMu first, then
// fpMu; unlock in reverse via defer. No other method takes the locks in
// reverse order, so no deadlock.
func (cm *CooldownManager) CheckAndSetWithGroup(
	fingerprint string, fpTTL time.Duration,
	groupKey string, groupTTL time.Duration,
) CooldownOutcome {
	now := time.Now()

	if groupKey == "" || groupTTL == 0 {
		cm.fpMu.Lock()
		defer cm.fpMu.Unlock()
		if checkAndSetLocked(cm.fpEntries, fingerprint, fpTTL, now) {
			return CooldownAccepted
		}
		return CooldownFingerprint
	}

	cm.groupMu.Lock()
	defer cm.groupMu.Unlock()
	if !checkAndSetLocked(cm.groupEntries, groupKey, groupTTL, now) {
		return CooldownGroup
	}

	cm.fpMu.Lock()
	defer cm.fpMu.Unlock()
	if !checkAndSetLocked(cm.fpEntries, fingerprint, fpTTL, now) {
		// Rollback the group entry so the maps stay consistent.
		delete(cm.groupEntries, groupKey)
		return CooldownFingerprint
	}
	return CooldownAccepted
}

// checkAndSetLocked is the lock-free body shared by CheckAndSet and
// CheckAndSetGroup. Caller must hold the relevant mutex.
func checkAndSetLocked(entries map[string]cooldownEntry, key string, ttl time.Duration, now time.Time) bool {
	for k, v := range entries {
		// Use >= so entries at exactly their TTL boundary are swept on the same
		// call that the check already treats them as expired (< ttl is false).
		// Using > would leave a "ghost" entry that lingers until elapsed > ttl,
		// making the sweep semantics inconsistent with the check below.
		if now.Sub(v.setAt) >= v.ttl {
			delete(entries, k)
		}
	}
	if entry, ok := entries[key]; ok {
		if now.Sub(entry.setAt) < entry.ttl {
			return false
		}
	}
	entries[key] = cooldownEntry{setAt: now, ttl: ttl}
	return true
}
