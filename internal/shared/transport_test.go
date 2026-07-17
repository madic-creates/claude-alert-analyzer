package shared

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

type mockRoundTripper struct {
	resp *http.Response
	err  error
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.resp, nil
}

func newOKResponse(body []byte) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}

func TestLimitedTransport_OversizedBodyCapped(t *testing.T) {
	oversize := make([]byte, MaxResponseBytes+1024)
	for i := range oversize {
		oversize[i] = 'A'
	}
	inner := &mockRoundTripper{resp: newOKResponse(oversize)}

	lt := NewLimitedTransport(inner, nil)
	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)

	resp, err := lt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	read, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if int64(len(read)) != MaxResponseBytes {
		t.Errorf("expected body capped to %d bytes, got %d", MaxResponseBytes, len(read))
	}
}

// TestLimitedTransport_ExactBodySizeIsNotTruncated verifies the exact boundary
// of the io.LimitReader cap: a response body of exactly MaxResponseBytes must be
// returned in full. Paired with TestLimitedTransport_OversizedBodyCapped (body >
// MaxResponseBytes → reads exactly MaxResponseBytes), this closes the mutation gap
// where the limit guard could silently shift by one byte.
func TestLimitedTransport_ExactBodySizeIsNotTruncated(t *testing.T) {
	exact := make([]byte, MaxResponseBytes)
	for i := range exact {
		exact[i] = 'B'
	}
	inner := &mockRoundTripper{resp: newOKResponse(exact)}

	lt := NewLimitedTransport(inner, nil)
	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)

	resp, err := lt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	read, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if int64(len(read)) != MaxResponseBytes {
		t.Errorf("exact-size body: got %d bytes, want %d (no truncation at exact limit)", len(read), MaxResponseBytes)
	}
}

func TestLimitedTransport_HistogramObservedAfterBodyClose(t *testing.T) {
	hist := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "test_after_close_seconds",
		Help: "test",
	})
	inner := &mockRoundTripper{resp: newOKResponse([]byte(`{"ok":true}`))}
	lt := NewLimitedTransport(inner, hist)

	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	resp, err := lt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Histogram must NOT be observed yet — only RoundTrip has returned.
	var m1 dto.Metric
	if err := hist.Write(&m1); err != nil {
		t.Fatalf("hist.Write: %v", err)
	}
	if m1.Histogram.GetSampleCount() != 0 {
		t.Errorf("histogram should not be observed before Close, got count=%d", m1.Histogram.GetSampleCount())
	}

	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	var m2 dto.Metric
	if err := hist.Write(&m2); err != nil {
		t.Fatalf("hist.Write: %v", err)
	}
	if m2.Histogram.GetSampleCount() != 1 {
		t.Errorf("histogram should be observed exactly once after Close, got count=%d", m2.Histogram.GetSampleCount())
	}

	// Idempotency: second Close must not double-count.
	_ = resp.Body.Close()
	var m3 dto.Metric
	_ = hist.Write(&m3)
	if m3.Histogram.GetSampleCount() != 1 {
		t.Errorf("second Close should not double-count, got count=%d", m3.Histogram.GetSampleCount())
	}
}

func TestLimitedTransport_HistogramObservedOnTransportError(t *testing.T) {
	hist := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "test_transport_error_seconds",
		Help: "test",
	})
	inner := &mockRoundTripper{err: errors.New("connection refused")}
	lt := NewLimitedTransport(inner, hist)

	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	_, err := lt.RoundTrip(req)
	if err == nil {
		t.Fatal("expected an error from inner.RoundTrip")
	}

	var m dto.Metric
	if err := hist.Write(&m); err != nil {
		t.Fatalf("hist.Write: %v", err)
	}
	if m.Histogram.GetSampleCount() != 1 {
		t.Errorf("histogram should be observed on transport error, got count=%d", m.Histogram.GetSampleCount())
	}
}

func TestLimitedTransport_HistogramObservedOnSuccess(t *testing.T) {
	hist := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "test_success_seconds",
		Help: "test",
	})
	inner := &mockRoundTripper{resp: newOKResponse([]byte(`{"ok":true}`))}
	lt := NewLimitedTransport(inner, hist)

	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	resp, err := lt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var m dto.Metric
	_ = hist.Write(&m)
	if m.Histogram.GetSampleCount() != 1 {
		t.Errorf("expected 1 observation on success, got %d", m.Histogram.GetSampleCount())
	}
	if m.Histogram.GetSampleSum() <= 0 {
		t.Errorf("expected positive duration, got %f", m.Histogram.GetSampleSum())
	}
}

// TestLimitedTransport_RetryCounting verifies that the transport increments
// the retry counter for every SDK retry attempt, detected via the
// X-Stainless-Retry-Count header the anthropic-sdk-go sets on each attempt
// ("0" on the first try, "1", "2", ... on retries).
func TestLimitedTransport_RetryCounting(t *testing.T) {
	ctr := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "test_retries_total",
		Help: "test",
	})
	inner := &mockRoundTripper{resp: newOKResponse([]byte(`{}`))}
	lt := NewLimitedTransport(inner, nil).WithRetryCounter(ctr)

	doReq := func(retryHeader string) {
		t.Helper()
		inner.resp = newOKResponse([]byte(`{}`))
		req, _ := http.NewRequest(http.MethodPost, "http://example.com", nil)
		if retryHeader != "" {
			req.Header.Set("X-Stainless-Retry-Count", retryHeader)
		}
		resp, err := lt.RoundTrip(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
	}

	// First attempt (header "0") and header-less requests must not count.
	doReq("0")
	doReq("")
	var m dto.Metric
	_ = ctr.Write(&m)
	if got := m.Counter.GetValue(); got != 0 {
		t.Errorf("counter after non-retry requests = %v, want 0", got)
	}

	// Each retried attempt counts once, regardless of attempt number.
	doReq("1")
	doReq("2")
	m = dto.Metric{}
	_ = ctr.Write(&m)
	if got := m.Counter.GetValue(); got != 2 {
		t.Errorf("counter after two retried attempts = %v, want 2", got)
	}
}

// TestLimitedTransport_RetryCountingOnTransportError verifies a retried
// attempt is counted even when the attempt itself fails at the transport
// level — the retry happened, so it must be visible.
func TestLimitedTransport_RetryCountingOnTransportError(t *testing.T) {
	ctr := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "test_retries_err_total",
		Help: "test",
	})
	inner := &mockRoundTripper{err: errors.New("connection refused")}
	lt := NewLimitedTransport(inner, nil).WithRetryCounter(ctr)

	req, _ := http.NewRequest(http.MethodPost, "http://example.com", nil)
	req.Header.Set("X-Stainless-Retry-Count", "1")
	if _, err := lt.RoundTrip(req); err == nil {
		t.Fatal("expected transport error")
	}

	var m dto.Metric
	_ = ctr.Write(&m)
	if got := m.Counter.GetValue(); got != 1 {
		t.Errorf("counter after failed retried attempt = %v, want 1", got)
	}
}

// TestLimitedTransport_NoRetryCounterIsSafe verifies retried requests pass
// through unchanged when no counter is attached (tests and callers that do
// not opt in).
func TestLimitedTransport_NoRetryCounterIsSafe(t *testing.T) {
	inner := &mockRoundTripper{resp: newOKResponse([]byte(`{}`))}
	lt := NewLimitedTransport(inner, nil)

	req, _ := http.NewRequest(http.MethodPost, "http://example.com", nil)
	req.Header.Set("X-Stainless-Retry-Count", "3")
	resp, err := lt.RoundTrip(req) // must not panic
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = resp.Body.Close()
}

func TestLimitedTransport_HistogramObservedOnNonOK(t *testing.T) {
	hist := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "test_nonok_seconds",
		Help: "test",
	})
	resp429 := &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Body:       io.NopCloser(bytes.NewReader([]byte(`rate limited`))),
	}
	inner := &mockRoundTripper{resp: resp429}
	lt := NewLimitedTransport(inner, hist)

	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	resp, err := lt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var m dto.Metric
	_ = hist.Write(&m)
	if m.Histogram.GetSampleCount() != 1 {
		t.Errorf("expected 1 observation on non-OK, got %d", m.Histogram.GetSampleCount())
	}
}
