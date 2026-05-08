package shared

import (
	"sync"
	"time"
)

// StormDetector counts incoming alerts in a 5-minute sliding window
// (5 buckets × 1 minute) and reports whether the configured threshold
// has been exceeded.
//
// THRESHOLD=0 is encoded as a nil receiver: NewStormDetector(0, _) returns
// nil. Methods are nil-safe so callers do not need to special-case the
// disabled state.
type StormDetector struct {
	threshold int
	now       func() time.Time

	mu      sync.Mutex
	buckets [5]bucket
}

type bucket struct {
	minute int64 // Unix minute (-1 = empty)
	count  int
}

// NewStormDetector returns a detector with the given threshold and clock.
// threshold <= 0 returns nil ("disabled").
func NewStormDetector(threshold int, now func() time.Time) *StormDetector {
	if threshold <= 0 {
		return nil
	}
	if now == nil {
		now = time.Now
	}
	d := &StormDetector{threshold: threshold, now: now}
	for i := range d.buckets {
		d.buckets[i].minute = -1
	}
	return d
}

// Threshold returns the configured threshold (0 if disabled).
func (d *StormDetector) Threshold() int {
	if d == nil {
		return 0
	}
	return d.threshold
}

// Record increments the bucket for the current minute.
// Nil-safe: no-op when the detector is disabled.
func (d *StormDetector) Record() {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	minute := d.now().Unix() / 60
	idx := int(minute%5+5) % 5 // safe modulo for negative time (test clocks)
	if d.buckets[idx].minute != minute {
		d.buckets[idx] = bucket{minute: minute, count: 1}
		return
	}
	d.buckets[idx].count++
}

// Count returns the total count over the last 5 minutes (including the
// current one). Nil-safe: returns 0 when the detector is disabled.
func (d *StormDetector) Count() int {
	if d == nil {
		return 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	minute := d.now().Unix() / 60
	cutoff := minute - 4
	var total int
	for _, b := range d.buckets {
		if b.minute >= cutoff {
			total += b.count
		}
	}
	return total
}
