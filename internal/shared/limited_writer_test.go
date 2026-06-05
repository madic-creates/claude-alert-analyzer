package shared

import (
	"sync"
	"testing"
)

func TestLimitedWriter_DiscardsBeyondLimit(t *testing.T) {
	lw := NewLimitedWriter(5)

	// First write: fits within limit.
	n, err := lw.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 {
		t.Errorf("n = %d, want 5", n)
	}
	if out, _ := lw.Snapshot(); out != "hello" {
		t.Errorf("buf = %q, want %q", out, "hello")
	}

	// Second write: limit already reached — full discard.
	n, err = lw.Write([]byte("world"))
	if err != nil {
		t.Fatalf("unexpected error on discard write: %v", err)
	}
	// Must pretend success (return full len) so the SSH/exec packages don't error.
	if n != 5 {
		t.Errorf("n = %d on discard, want 5", n)
	}
	// Buffer must not have grown.
	if out, _ := lw.Snapshot(); out != "hello" {
		t.Errorf("buf = %q after discard, want %q", out, "hello")
	}
}

func TestLimitedWriter_PartialWrite(t *testing.T) {
	lw := NewLimitedWriter(3)

	// Write 5 bytes when only 3 remain → 3 written, 2 discarded.
	n, err := lw.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 {
		t.Errorf("n = %d, want 5 (full slice length)", n)
	}
	if out, _ := lw.Snapshot(); out != "hel" {
		t.Errorf("buf = %q, want %q", out, "hel")
	}
	if lw.Remaining() != 0 {
		t.Errorf("remaining = %d, want 0 after partial write fills buffer", lw.Remaining())
	}
}

func TestLimitedWriter_ZeroRemaining(t *testing.T) {
	lw := NewLimitedWriter(0)

	n, err := lw.Write([]byte("anything"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 8 {
		t.Errorf("n = %d, want 8", n)
	}
	if out, _ := lw.Snapshot(); len(out) != 0 {
		t.Errorf("buf should remain empty, got %q", out)
	}
}

func TestLimitedWriter_TruncatedFlag(t *testing.T) {
	t.Run("no truncation when data fits", func(t *testing.T) {
		lw := NewLimitedWriter(10)
		_, _ = lw.Write([]byte("hello"))
		if _, truncated := lw.Snapshot(); truncated {
			t.Error("truncated should be false when all data fits within limit")
		}
	})

	t.Run("truncated set on partial write", func(t *testing.T) {
		lw := NewLimitedWriter(3)
		_, _ = lw.Write([]byte("hello")) // 5 bytes, only 3 fit
		if _, truncated := lw.Snapshot(); !truncated {
			t.Error("truncated should be true after a partial write")
		}
	})

	t.Run("truncated set on full discard", func(t *testing.T) {
		lw := NewLimitedWriter(0)
		_, _ = lw.Write([]byte("anything"))
		if _, truncated := lw.Snapshot(); !truncated {
			t.Error("truncated should be true when writing to a full buffer")
		}
	})
}

func TestLimitedWriter_Basic(t *testing.T) {
	lw := NewLimitedWriter(10)
	n, err := lw.Write([]byte("hello"))
	if err != nil || n != 5 {
		t.Fatalf("Write(hello): n=%d err=%v", n, err)
	}
	out, truncated := lw.Snapshot()
	if out != "hello" {
		t.Errorf("buf=%q, want %q", out, "hello")
	}
	if truncated {
		t.Errorf("truncated prematurely")
	}
}

func TestLimitedWriter_Truncation(t *testing.T) {
	lw := NewLimitedWriter(5)
	n, err := lw.Write([]byte("hello world"))
	if err != nil || n != 11 {
		t.Fatalf("Write should report all bytes consumed: n=%d err=%v", n, err)
	}
	out, truncated := lw.Snapshot()
	if out != "hello" {
		t.Errorf("buf=%q, want %q", out, "hello")
	}
	if !truncated {
		t.Errorf("expected truncated=true")
	}
	// Further writes should be discarded silently.
	n, err = lw.Write([]byte("more"))
	if err != nil || n != 4 {
		t.Fatalf("Write after limit: n=%d err=%v", n, err)
	}
	if out, _ := lw.Snapshot(); out != "hello" {
		t.Errorf("buf changed after limit: %q", out)
	}
}

func TestLimitedWriter_ConcurrentSafety(t *testing.T) {
	const goroutines = 20
	const chunk = "abcdefghij" // 10 bytes each
	lw := NewLimitedWriter(goroutines * len(chunk))
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lw.Write([]byte(chunk)) //nolint:errcheck
		}()
	}
	wg.Wait()
	if out, _ := lw.Snapshot(); len(out) != goroutines*len(chunk) {
		t.Errorf("len(out)=%d, want %d", len(out), goroutines*len(chunk))
	}
}

// TestLimitedWriter_ExactFitDoesNotSetTruncated verifies the exact boundary of
// the partial-write guard: a write whose size equals the remaining capacity
// (n == remaining) must NOT set the truncated flag. The guard is
// `if n > lw.remaining`, so n == remaining is strictly in-bounds.
// A mutation of '>' to '>=' would incorrectly mark the write as truncated.
// All existing "no truncation" tests write well under the limit (e.g. 5 bytes
// into a 10-byte buffer), so the mutation would pass them undetected.
func TestLimitedWriter_ExactFitDoesNotSetTruncated(t *testing.T) {
	lw := NewLimitedWriter(5)
	n, err := lw.Write([]byte("hello")) // exactly 5 bytes == limit
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 {
		t.Errorf("n = %d, want 5", n)
	}
	out, truncated := lw.Snapshot()
	if out != "hello" {
		t.Errorf("buf = %q, want \"hello\"", out)
	}
	if truncated {
		t.Errorf("truncated = true for an exact-fit write (n == remaining); want false")
	}
	if rem := lw.Remaining(); rem != 0 {
		t.Errorf("remaining = %d, want 0 after exact-fit write", rem)
	}
}
