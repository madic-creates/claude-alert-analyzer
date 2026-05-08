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
// neither, in fixed lock order (groupMu → fpMu). Returns false if either is
// already in cooldown; in that case nothing is mutated.
//
// groupKey == "" or groupTTL == 0 → group is skipped entirely; the call
// reduces to CheckAndSet on the fingerprint alone (with the same locking).
//
// Lock-Discipline: BOTH mutexes are held over the entire decision (not
// taken individually and released between steps). Order: groupMu first, then
// fpMu; unlock in reverse via defer. No other method takes the locks in
// reverse order, so no deadlock.
func (cm *CooldownManager) CheckAndSetWithGroup(
	fingerprint string, fpTTL time.Duration,
	groupKey string, groupTTL time.Duration,
) bool {
	now := time.Now()

	if groupKey == "" || groupTTL == 0 {
		cm.fpMu.Lock()
		defer cm.fpMu.Unlock()
		return checkAndSetLocked(cm.fpEntries, fingerprint, fpTTL, now)
	}

	cm.groupMu.Lock()
	defer cm.groupMu.Unlock()
	if !checkAndSetLocked(cm.groupEntries, groupKey, groupTTL, now) {
		return false
	}

	cm.fpMu.Lock()
	defer cm.fpMu.Unlock()
	if !checkAndSetLocked(cm.fpEntries, fingerprint, fpTTL, now) {
		// Rollback the group entry so the maps stay consistent.
		delete(cm.groupEntries, groupKey)
		return false
	}
	return true
}

// checkAndSetLocked is the lock-free body shared by CheckAndSet and
// CheckAndSetGroup. Caller must hold the relevant mutex.
func checkAndSetLocked(entries map[string]cooldownEntry, key string, ttl time.Duration, now time.Time) bool {
	for k, v := range entries {
		if now.Sub(v.setAt) > v.ttl {
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
