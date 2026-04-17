package shared

import (
	"sync"
	"time"
)

type cooldownEntry struct {
	setAt time.Time
	ttl   time.Duration
}

type CooldownManager struct {
	mu      sync.Mutex
	entries map[string]cooldownEntry
}

func NewCooldownManager() *CooldownManager {
	return &CooldownManager{entries: make(map[string]cooldownEntry)}
}

// CheckAndSet returns true and records the fingerprint if it is not currently
// in cooldown; otherwise it returns false. Each entry is expired using its own
// TTL so that callers with different TTLs do not interfere with each other.
func (cm *CooldownManager) CheckAndSet(fingerprint string, ttl time.Duration) bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	now := time.Now()

	// Sweep expired entries using each entry's own TTL, not the current TTL.
	for k, v := range cm.entries {
		if now.Sub(v.setAt) > v.ttl {
			delete(cm.entries, k)
		}
	}

	if entry, ok := cm.entries[fingerprint]; ok {
		if now.Sub(entry.setAt) < entry.ttl {
			return false
		}
	}

	cm.entries[fingerprint] = cooldownEntry{setAt: now, ttl: ttl}
	return true
}

func (cm *CooldownManager) Clear(fingerprint string) {
	cm.mu.Lock()
	delete(cm.entries, fingerprint)
	cm.mu.Unlock()
}
