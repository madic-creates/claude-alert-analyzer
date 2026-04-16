package shared

import (
	"sync"
	"time"
)

type cooldownEntry struct {
	setAt time.Time
}

type CooldownManager struct {
	mu      sync.Mutex
	entries map[string]cooldownEntry
}

func NewCooldownManager() *CooldownManager {
	return &CooldownManager{entries: make(map[string]cooldownEntry)}
}

func (cm *CooldownManager) CheckAndSet(fingerprint string, ttl time.Duration) bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	now := time.Now()

	for k, v := range cm.entries {
		if now.Sub(v.setAt) > ttl {
			delete(cm.entries, k)
		}
	}

	if entry, ok := cm.entries[fingerprint]; ok {
		if now.Sub(entry.setAt) < ttl {
			return false
		}
	}

	cm.entries[fingerprint] = cooldownEntry{setAt: now}
	return true
}

func (cm *CooldownManager) Clear(fingerprint string) {
	cm.mu.Lock()
	delete(cm.entries, fingerprint)
	cm.mu.Unlock()
}
