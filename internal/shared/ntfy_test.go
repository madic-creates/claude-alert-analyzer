package shared

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

func TestNtfyPublisher_Publish_Success(t *testing.T) {
	var gotTitle, gotPriority, gotBody, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTitle = r.Header.Get("Title")
		gotPriority = r.Header.Get("Priority")
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := &NtfyPublisher{HTTP: srv.Client(), URL: srv.URL, Topic: "alerts", Token: "tok123"}
	err := p.Publish(context.Background(), "Test Alert", "high", "something broke")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if gotTitle != "Test Alert" {
		t.Errorf("Title header: got %q, want %q", gotTitle, "Test Alert")
	}
	if gotPriority != "high" {
		t.Errorf("Priority header: got %q, want %q", gotPriority, "high")
	}
	if gotAuth != "Bearer tok123" {
		t.Errorf("Authorization header: got %q, want %q", gotAuth, "Bearer tok123")
	}
	if !strings.Contains(gotBody, "something broke") {
		t.Errorf("body not sent: %q", gotBody)
	}
}

func TestNtfyPublisher_Publish_NoToken(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := &NtfyPublisher{HTTP: srv.Client(), URL: srv.URL, Topic: "alerts", Token: ""}
	if err := p.Publish(context.Background(), "t", "default", "body"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAuth != "" {
		t.Errorf("expected no Authorization header, got %q", gotAuth)
	}
}

func TestNtfyPublisher_Publish_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	p := &NtfyPublisher{HTTP: srv.Client(), URL: srv.URL, Topic: "alerts"}
	err := p.Publish(context.Background(), "t", "default", "body")
	if err == nil {
		t.Fatal("expected error for 403 response")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error should mention status code, got: %v", err)
	}
}

// TestNtfyPublisher_Publish_TruncatesLongTitle verifies that titles exceeding
// maxNtfyTitleBytes are trimmed before sending. ntfy rejects over-length titles
// with 400 Bad Request, causing repeated publish failures for alerts whose
// title is derived from long hostnames or service descriptions.
func TestNtfyPublisher_Publish_TruncatesLongTitle(t *testing.T) {
	var gotTitle string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTitle = r.Header.Get("Title")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := &NtfyPublisher{HTTP: srv.Client(), URL: srv.URL, Topic: "alerts"}
	longTitle := strings.Repeat("A", maxNtfyTitleBytes*2)
	if err := p.Publish(context.Background(), longTitle, "default", "body"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gotTitle) > maxNtfyTitleBytes {
		t.Errorf("title not truncated: sent %d bytes, want <= %d", len(gotTitle), maxNtfyTitleBytes)
	}
	if !strings.HasSuffix(gotTitle, "...") {
		t.Errorf("expected truncated title to end with '...', got: %q", gotTitle[max(0, len(gotTitle)-10):])
	}
}

// TestNtfyPublisher_Publish_TruncatesLongTitleUTF8 verifies that title
// truncation preserves valid UTF-8 when a multi-byte character straddles the
// cut boundary. cutAt = maxNtfyTitleBytes - 3 = 247; if the first byte of a
// 4-byte emoji lands at position 244, a naive title[:247] would include 3
// bytes of an incomplete sequence. strings.ToValidUTF8 must strip those bytes
// so the transmitted header is valid UTF-8 and within maxNtfyTitleBytes.
func TestNtfyPublisher_Publish_TruncatesLongTitleUTF8(t *testing.T) {
	var gotTitle string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTitle = r.Header.Get("Title")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := &NtfyPublisher{HTTP: srv.Client(), URL: srv.URL, Topic: "alerts"}
	// Place a 4-byte emoji at byte 244 so that the cut point (247) falls
	// inside the emoji, forcing the UTF-8 boundary trimming to kick in.
	emoji := "🔥" // 4 bytes: 0xF0 0x9F 0x94 0xA5
	title := strings.Repeat("x", 244) + emoji + strings.Repeat("y", 50)
	if err := p.Publish(context.Background(), title, "default", "body"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gotTitle) > maxNtfyTitleBytes {
		t.Errorf("title not truncated: sent %d bytes, want <= %d", len(gotTitle), maxNtfyTitleBytes)
	}
	if !utf8.ValidString(gotTitle) {
		t.Errorf("truncated title is not valid UTF-8: %q", gotTitle)
	}
	if !strings.HasSuffix(gotTitle, "...") {
		t.Errorf("expected truncated title to end with '...', got: %q", gotTitle)
	}
}

// TestNtfyPublisher_Publish_ShortTitleUnchanged verifies that titles within
// the limit are not modified.
func TestNtfyPublisher_Publish_ShortTitleUnchanged(t *testing.T) {
	var gotTitle string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTitle = r.Header.Get("Title")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	const shortTitle = "Analysis: web01 - CPU Usage"
	p := &NtfyPublisher{HTTP: srv.Client(), URL: srv.URL, Topic: "alerts"}
	if err := p.Publish(context.Background(), shortTitle, "default", "body"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotTitle != shortTitle {
		t.Errorf("short title modified: got %q, want %q", gotTitle, shortTitle)
	}
}

func TestNtfyPublisher_Publish_TruncatesLargeBody(t *testing.T) {
	var receivedLen int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		receivedLen = len(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := &NtfyPublisher{HTTP: srv.Client(), URL: srv.URL, Topic: "alerts"}
	largeBody := strings.Repeat("x", maxNtfyBodyBytes*2)
	if err := p.Publish(context.Background(), "t", "default", largeBody); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Body should be truncated to near maxNtfyBodyBytes (plus truncation marker).
	if receivedLen > maxNtfyBodyBytes+50 {
		t.Errorf("body not truncated: received %d bytes", receivedLen)
	}
}

func TestNtfyPublisher_Publish_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	p := &NtfyPublisher{HTTP: srv.Client(), URL: srv.URL, Topic: "alerts"}
	err := p.Publish(ctx, "t", "default", "body")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestNtfyPublisher_Name(t *testing.T) {
	p := &NtfyPublisher{}
	if p.Name() != "ntfy" {
		t.Errorf("Name() = %q, want %q", p.Name(), "ntfy")
	}
}

// fakePublisher is a test implementation of Publisher.
type fakePublisher struct {
	name string
	err  error
	calls int
}

func (f *fakePublisher) Name() string { return f.name }
func (f *fakePublisher) Publish(_ context.Context, _, _, _ string) error {
	f.calls++
	return f.err
}

func TestPublishAll_AllSucceed(t *testing.T) {
	p1 := &fakePublisher{name: "p1"}
	p2 := &fakePublisher{name: "p2"}

	err := PublishAll(context.Background(), []Publisher{p1, p2}, "title", "default", "body")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p1.calls != 1 || p2.calls != 1 {
		t.Errorf("expected each publisher called once: p1=%d p2=%d", p1.calls, p2.calls)
	}
}

func TestPublishAll_OneFailsReturnsFirstError(t *testing.T) {
	errFirst := errors.New("first failure")
	p1 := &fakePublisher{name: "p1", err: errFirst}
	p2 := &fakePublisher{name: "p2"}

	err := PublishAll(context.Background(), []Publisher{p1, p2}, "title", "default", "body")
	if !errors.Is(err, errFirst) {
		t.Errorf("expected first error, got: %v", err)
	}
	// p2 should still have been called.
	if p2.calls != 1 {
		t.Errorf("expected p2 to be called, calls=%d", p2.calls)
	}
}

func TestPublishAll_AllFail(t *testing.T) {
	errA := errors.New("err-a")
	errB := errors.New("err-b")
	p1 := &fakePublisher{name: "p1", err: errA}
	p2 := &fakePublisher{name: "p2", err: errB}

	err := PublishAll(context.Background(), []Publisher{p1, p2}, "title", "default", "body")
	// Should return first error encountered (p1's).
	if !errors.Is(err, errA) {
		t.Errorf("expected err-a, got: %v", err)
	}
}

func TestPublishAll_Empty(t *testing.T) {
	err := PublishAll(context.Background(), nil, "title", "default", "body")
	if err != nil {
		t.Fatalf("unexpected error for empty publisher list: %v", err)
	}
}

// TestNtfyPublisher_Publish_RetryOn5xx verifies that a 5xx response is retried
// and ultimately succeeds on a later attempt.
func TestNtfyPublisher_Publish_RetryOn5xx(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount < 3 {
			w.WriteHeader(http.StatusServiceUnavailable) // 503
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := &NtfyPublisher{HTTP: srv.Client(), URL: srv.URL, Topic: "alerts", RetryDelays: []time.Duration{0, 0}}
	err := p.Publish(context.Background(), "t", "default", "body")
	if err != nil {
		t.Fatalf("expected success after retries, got: %v", err)
	}
	if callCount != 3 {
		t.Errorf("expected 3 attempts, got %d", callCount)
	}
}

// TestNtfyPublisher_Publish_ExhaustsRetries verifies that after all retries are
// exhausted the last error is returned.
func TestNtfyPublisher_Publish_ExhaustsRetries(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusInternalServerError) // 500 every time
	}))
	defer srv.Close()

	p := &NtfyPublisher{HTTP: srv.Client(), URL: srv.URL, Topic: "alerts", RetryDelays: []time.Duration{0, 0}}
	err := p.Publish(context.Background(), "t", "default", "body")
	if err == nil {
		t.Fatal("expected error after all retries exhausted")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention status code, got: %v", err)
	}
	// 1 initial attempt + 2 retries = 3 total.
	if callCount != 3 {
		t.Errorf("expected 3 total attempts, got %d", callCount)
	}
}

// TestNtfyPublisher_Publish_RetryOn429 verifies that a 429 Too Many Requests
// response is retried, because rate limits are transient and retrying is the
// correct recovery strategy.
func TestNtfyPublisher_Publish_RetryOn429(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount < 3 {
			w.WriteHeader(http.StatusTooManyRequests) // 429
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := &NtfyPublisher{HTTP: srv.Client(), URL: srv.URL, Topic: "alerts", RetryDelays: []time.Duration{0, 0}}
	err := p.Publish(context.Background(), "t", "default", "body")
	if err != nil {
		t.Fatalf("expected success after retries on 429, got: %v", err)
	}
	if callCount != 3 {
		t.Errorf("expected 3 attempts (2 rate-limited + 1 success), got %d", callCount)
	}
}

// TestNtfyPublisher_Publish_NoRetryOn4xx verifies that 4xx errors are not retried.
func TestNtfyPublisher_Publish_NoRetryOn4xx(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusUnauthorized) // 401
	}))
	defer srv.Close()

	p := &NtfyPublisher{HTTP: srv.Client(), URL: srv.URL, Topic: "alerts", RetryDelays: []time.Duration{0, 0}}
	err := p.Publish(context.Background(), "t", "default", "body")
	if err == nil {
		t.Fatal("expected error for 401 response")
	}
	if callCount != 1 {
		t.Errorf("expected exactly 1 attempt (no retry on 4xx), got %d", callCount)
	}
}

// TestNtfyPublisher_Publish_DrainsBodyForConnectionReuse verifies that when ntfy
// returns a non-2xx response, the full response body is consumed before Close so
// Go's HTTP transport can return the connection to the pool. Without draining,
// each retry opens a new TCP connection (connection churn), observable via the
// server-side ConnState callback counting distinct new connections.
func TestNtfyPublisher_Publish_DrainsBodyForConnectionReuse(t *testing.T) {
	var mu sync.Mutex
	conns := make(map[net.Conn]struct{})

	callCount := 0
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			// Body is much larger than the 256-byte snippet read cap; if the
			// remainder is not drained the transport cannot reuse the connection.
			fmt.Fprint(w, strings.Repeat("x", 2048))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	srv.Config.ConnState = func(c net.Conn, state http.ConnState) {
		if state == http.StateNew {
			mu.Lock()
			conns[c] = struct{}{}
			mu.Unlock()
		}
	}
	srv.Start()
	defer srv.Close()

	p := &NtfyPublisher{HTTP: srv.Client(), URL: srv.URL, Topic: "alerts", RetryDelays: []time.Duration{0, 0}}
	if err := p.Publish(context.Background(), "t", "default", "body"); err != nil {
		t.Fatalf("expected success after retries, got: %v", err)
	}
	if callCount != 3 {
		t.Errorf("expected 3 attempts, got %d", callCount)
	}

	mu.Lock()
	numConns := len(conns)
	mu.Unlock()

	// All three attempts should share a single TCP connection. Reuse is only
	// possible when the response body is fully drained before Close.
	if numConns != 1 {
		t.Errorf("expected 1 TCP connection (body drained for reuse), got %d; response body not fully consumed before Close", numConns)
	}
}

// TestNtfyPublisher_Publish_RetryContextCancelled verifies that a cancelled
// context aborts retries before the next delay completes.
func TestNtfyPublisher_Publish_RetryContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel after the first failed attempt triggers a retry delay.
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	p := &NtfyPublisher{HTTP: srv.Client(), URL: srv.URL, Topic: "alerts", RetryDelays: []time.Duration{5 * time.Second, 5 * time.Second}}
	err := p.Publish(ctx, "t", "default", "body")
	if err == nil {
		t.Fatal("expected error when context cancelled during retry")
	}
}
