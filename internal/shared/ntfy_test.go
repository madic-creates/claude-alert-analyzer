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
	"sync/atomic"
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

// TestNtfyPublisher_Publish_TitleControlCharsStripped verifies that control
// characters embedded in the title are removed before it is used as an HTTP
// header value. RFC 7230 §3.2.6 prohibits C0 control characters in header
// field values; Go's HTTP transport rejects such requests outright, which
// would cause every publish attempt to fail silently after retries for alerts
// whose title is derived from a CheckMK service description or Alertmanager
// label containing an embedded newline.
func TestNtfyPublisher_Publish_TitleControlCharsStripped(t *testing.T) {
	var gotTitle string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTitle = r.Header.Get("Title")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := &NtfyPublisher{HTTP: srv.Client(), URL: srv.URL, Topic: "alerts"}
	// Title with embedded newline, carriage return, and null byte — all C0
	// control characters that Go's HTTP client would reject as invalid header
	// values. The clean text on either side must be preserved.
	dirtyTitle := "Analysis: web01\nfake-section\r\x00 - CPU Usage"
	if err := p.Publish(context.Background(), dirtyTitle, "default", "body"); err != nil {
		t.Fatalf("expected no error after control char stripping, got: %v", err)
	}
	// Control characters must be absent from the transmitted header.
	for _, ch := range []string{"\n", "\r", "\x00"} {
		if strings.Contains(gotTitle, ch) {
			t.Errorf("control char %q not stripped from title: %q", ch, gotTitle)
		}
	}
	// The printable portion of the title must be preserved.
	if !strings.Contains(gotTitle, "Analysis: web01") {
		t.Errorf("clean title prefix not preserved: %q", gotTitle)
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
	name  string
	err   error
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

func TestPublishAll_OneFails_AllPublishersStillCalled(t *testing.T) {
	errFirst := errors.New("first failure")
	p1 := &fakePublisher{name: "p1", err: errFirst}
	p2 := &fakePublisher{name: "p2"}

	err := PublishAll(context.Background(), []Publisher{p1, p2}, "title", "default", "body")
	if !errors.Is(err, errFirst) {
		t.Errorf("expected error to wrap first failure, got: %v", err)
	}
	// p2 should still have been called despite p1's failure.
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
	// Should return a joined error containing all failures so callers see every
	// failed publisher, not just the first one.
	if !errors.Is(err, errA) {
		t.Errorf("expected err-a in joined error, got: %v", err)
	}
	if !errors.Is(err, errB) {
		t.Errorf("expected err-b in joined error, got: %v", err)
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

// TestNtfyPublisher_Publish_RedactsErrorBodySnippet verifies that when ntfy
// (or a reverse proxy in front of it) returns a non-2xx response whose body
// contains a credential — e.g. an upstream that reflects the request's
// Authorization header into the error page — the snippet embedded in the
// returned error is passed through RedactSecrets. Without this, the bearer
// token would flow into the slog.Error("publish failed", ...) at PublishAll
// and into any joined error returned to the caller. Mirrors the redaction
// pattern at k8s/context.go:80-82 and checkmk/context.go:163-164,247.
func TestNtfyPublisher_Publish_RedactsErrorBodySnippet(t *testing.T) {
	const leakedToken = "Authorization: Bearer sk-ant-abc123secret456"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "Upstream rejected request with "+leakedToken)
	}))
	defer srv.Close()

	p := &NtfyPublisher{HTTP: srv.Client(), URL: srv.URL, Topic: "alerts"}
	err := p.Publish(context.Background(), "t", "default", "body")
	if err == nil {
		t.Fatal("expected error for 400 response")
	}
	msg := err.Error()
	if !strings.Contains(msg, "400") {
		t.Errorf("error should mention status code, got: %v", err)
	}
	if strings.Contains(msg, "sk-ant-abc123secret456") {
		t.Errorf("raw token leaked into error message: %s", msg)
	}
	if !strings.Contains(msg, "[REDACTED]") {
		t.Errorf("redaction marker missing from error message: %s", msg)
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

// TestNtfyPublisher_Publish_DrainsLargeErrorBodyForConnectionReuse verifies
// that the drain cap is large enough to consume a realistic reverse-proxy
// error page (e.g. a Cloudflare or nginx HTML error response sitting in front
// of ntfy). The previous 4 KiB drain cap silently defeated connection reuse
// whenever the error body exceeded ~4 KiB — every retry would open a fresh TCP
// (and on real deployments TLS) connection, multiplying latency during storms.
func TestNtfyPublisher_Publish_DrainsLargeErrorBodyForConnectionReuse(t *testing.T) {
	var mu sync.Mutex
	conns := make(map[net.Conn]struct{})

	callCount := 0
	// 32 KiB body — well above the previous 4 KiB cap, well below the new
	// MaxBodyDrainBytes (64 KiB). Mirrors the size of a typical HTML error
	// page returned by a CDN or reverse proxy.
	const largeErrorBodySize = 32 * 1024
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, strings.Repeat("x", largeErrorBodySize))
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

	if numConns != 1 {
		t.Errorf("expected 1 TCP connection for a %d-byte error body (full drain enables reuse), got %d", largeErrorBodySize, numConns)
	}
}

// TestNtfyPublisher_Publish_RetryBiasTowardCancel verifies that when ctx.Done()
// and the retry-delay timer become ready at the same instant, Publish returns
// the cancellation immediately rather than racing into a doomed HTTP attempt.
//
// Without the post-select cancellation re-check, Go's random select would take
// timer.C ~50% of the time when both channels are ready simultaneously,
// causing one extra HTTP roundtrip per Publish during graceful shutdown plus
// a misleading "retrying ntfy publish" log line. The test stages the race by
// (a) cancelling ctx after the first failed attempt buffers lastErr, then (b)
// using a one-shot test hook to block the goroutine inside Publish until the
// timer has fired, so that by the time the post-select check runs, both
// ctx.Done() and timer.C are ready. The hook is installed inside a sync.Once
// so it fires exactly once per test, deterministically catching the race
// window: 100 iterations × ~0% chance of false negative ≈ 0 in practice.
func TestNtfyPublisher_Publish_RetryBiasTowardCancel(t *testing.T) {
	prev := testHookBeforeNtfyRetryRecheck
	defer func() { testHookBeforeNtfyRetryRecheck = prev }()

	for i := 0; i < 100; i++ {
		var attemptCount int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&attemptCount, 1)
			w.WriteHeader(http.StatusServiceUnavailable)
		}))

		ctx, cancel := context.WithCancel(context.Background())

		// One-shot hook: cancel ctx the first time the post-select check
		// is about to run. By that point the retry-delay timer has already
		// fired and selected the timer.C branch — so ctx.Done() and the
		// authoritative "must abort" signal are *both* ready when the
		// re-check executes. Without the bias guard, Publish would proceed
		// to a doomed second HTTP attempt; with the guard, it returns the
		// cancellation immediately.
		var once sync.Once
		testHookBeforeNtfyRetryRecheck = func() {
			once.Do(func() { cancel() })
		}

		p := &NtfyPublisher{
			HTTP:        srv.Client(),
			URL:         srv.URL,
			Topic:       "alerts",
			RetryDelays: []time.Duration{0, 0},
		}
		err := p.Publish(ctx, "t", "default", "body")
		srv.Close()
		cancel()

		if err == nil {
			t.Fatalf("iteration %d: expected error, got nil", i)
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("iteration %d: expected error to wrap context.Canceled, got: %v", i, err)
		}
		// The 503 from the first attempt must be preserved in the error so
		// operators still see why the retry was happening.
		if !strings.Contains(err.Error(), "503") {
			t.Fatalf("iteration %d: expected error to contain last HTTP status (503), got: %v", i, err)
		}
		// Exactly one HTTP attempt must have reached the server. A second
		// attempt would mean the bias check failed to short-circuit and
		// timer.C continued to the doomed HTTP call.
		if got := atomic.LoadInt32(&attemptCount); got != 1 {
			t.Fatalf("iteration %d: expected exactly 1 HTTP attempt (bias short-circuits after timer wins), got %d", i, got)
		}
	}
}

// TestNtfyPublisher_Publish_RetryContextCancelled verifies that a cancelled
// context aborts retries before the next delay completes and that the returned
// error wraps both the context error and the last HTTP error so callers can
// diagnose what originally caused the retries.
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
	// The returned error must wrap the context cancellation so callers can
	// distinguish shutdown-induced aborts from permanent publish failures.
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected error to wrap context.Canceled, got: %v", err)
	}
	// The last HTTP error from the failed attempt must also be present so
	// operators can see why retries were happening in the first place.
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("expected error to contain last HTTP status (503), got: %v", err)
	}
}
