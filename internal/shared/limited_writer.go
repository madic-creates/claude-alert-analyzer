package shared

import (
	"bytes"
	"io"
	"sync"
)

// LimitedWriter writes to an internal buffer until the byte limit is reached,
// then silently discards further writes while still reporting success. It is
// safe for concurrent use — stdout and stderr may be written from different
// goroutines by exec and SSH packages.
type LimitedWriter struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	remaining int
	truncated bool
}

// NewLimitedWriter returns a LimitedWriter that buffers up to limit bytes.
func NewLimitedWriter(limit int) *LimitedWriter {
	return &LimitedWriter{remaining: limit}
}

func (lw *LimitedWriter) Write(p []byte) (int, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	if lw.remaining <= 0 {
		lw.truncated = true
		return len(p), nil // discard, but pretend success so callers don't error
	}
	n := len(p)
	if n > lw.remaining {
		p = p[:lw.remaining]
		lw.truncated = true // trailing bytes will be discarded after this write
	}
	written, err := lw.buf.Write(p)
	lw.remaining -= written
	// Return the original length so callers (exec, SSH packages) don't treat a
	// partial write as an error.
	return n, err
}

// Snapshot returns the current buffer contents and truncation flag under the
// internal lock. Safe to call concurrently with Write.
func (lw *LimitedWriter) Snapshot() (output string, truncated bool) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	return lw.buf.String(), lw.truncated
}

// Remaining returns the number of bytes still available for buffering.
func (lw *LimitedWriter) Remaining() int {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	return lw.remaining
}

// Ensure LimitedWriter implements io.Writer (compile-time check).
var _ io.Writer = (*LimitedWriter)(nil)
