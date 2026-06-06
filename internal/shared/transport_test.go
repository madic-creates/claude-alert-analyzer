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
