package shared

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

	p := &NtfyPublisher{URL: srv.URL, Topic: "alerts", Token: "tok123"}
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

	p := &NtfyPublisher{URL: srv.URL, Topic: "alerts", Token: ""}
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

	p := &NtfyPublisher{URL: srv.URL, Topic: "alerts"}
	err := p.Publish(context.Background(), "t", "default", "body")
	if err == nil {
		t.Fatal("expected error for 403 response")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error should mention status code, got: %v", err)
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

	p := &NtfyPublisher{URL: srv.URL, Topic: "alerts"}
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

	p := &NtfyPublisher{URL: srv.URL, Topic: "alerts"}
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
	// Speed up test by using instant delays.
	orig := ntfyRetryDelays
	ntfyRetryDelays = []time.Duration{0, 0}
	defer func() { ntfyRetryDelays = orig }()

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

	p := &NtfyPublisher{URL: srv.URL, Topic: "alerts"}
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
	orig := ntfyRetryDelays
	ntfyRetryDelays = []time.Duration{0, 0}
	defer func() { ntfyRetryDelays = orig }()

	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusInternalServerError) // 500 every time
	}))
	defer srv.Close()

	p := &NtfyPublisher{URL: srv.URL, Topic: "alerts"}
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

// TestNtfyPublisher_Publish_NoRetryOn4xx verifies that 4xx errors are not retried.
func TestNtfyPublisher_Publish_NoRetryOn4xx(t *testing.T) {
	orig := ntfyRetryDelays
	ntfyRetryDelays = []time.Duration{0, 0}
	defer func() { ntfyRetryDelays = orig }()

	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusUnauthorized) // 401
	}))
	defer srv.Close()

	p := &NtfyPublisher{URL: srv.URL, Topic: "alerts"}
	err := p.Publish(context.Background(), "t", "default", "body")
	if err == nil {
		t.Fatal("expected error for 401 response")
	}
	if callCount != 1 {
		t.Errorf("expected exactly 1 attempt (no retry on 4xx), got %d", callCount)
	}
}

// TestNtfyPublisher_Publish_RetryContextCancelled verifies that a cancelled
// context aborts retries before the next delay completes.
func TestNtfyPublisher_Publish_RetryContextCancelled(t *testing.T) {
	orig := ntfyRetryDelays
	ntfyRetryDelays = []time.Duration{5 * time.Second, 5 * time.Second} // long delays
	defer func() { ntfyRetryDelays = orig }()

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

	p := &NtfyPublisher{URL: srv.URL, Topic: "alerts"}
	err := p.Publish(ctx, "t", "default", "body")
	if err == nil {
		t.Fatal("expected error when context cancelled during retry")
	}
}
