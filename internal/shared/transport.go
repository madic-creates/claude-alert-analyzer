package shared

import (
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// MaxResponseBytes bounds the amount of data read from an API response body
// to prevent a malicious or buggy upstream from exhausting memory.
const MaxResponseBytes = 2 * 1024 * 1024 // 2 MiB

// LimitedTransport wraps an http.RoundTripper to (a) cap response body size at
// MaxResponseBytes and (b) observe round-trip latency in a Prometheus histogram
// when the body is closed.
type LimitedTransport struct {
	inner             http.RoundTripper
	maxBytes          int64
	durationHistogram prometheus.Observer // optional; nil = no observation
}

// NewLimitedTransport returns a LimitedTransport around inner. inner=nil falls
// back to http.DefaultTransport. hist=nil disables histogram observation.
func NewLimitedTransport(inner http.RoundTripper, hist prometheus.Observer) *LimitedTransport {
	if inner == nil {
		inner = http.DefaultTransport
	}
	return &LimitedTransport{
		inner:             inner,
		maxBytes:          MaxResponseBytes,
		durationHistogram: hist,
	}
}

func (lt *LimitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := lt.inner.RoundTrip(req)
	if err != nil {
		lt.observe(start)
		return nil, err
	}
	resp.Body = &timedLimitedReadCloser{
		r:       io.LimitReader(resp.Body, lt.maxBytes),
		c:       resp.Body,
		start:   start,
		observe: lt.observe,
	}
	return resp, nil
}

func (lt *LimitedTransport) observe(start time.Time) {
	if lt.durationHistogram != nil {
		lt.durationHistogram.Observe(time.Since(start).Seconds())
	}
}

// timedLimitedReadCloser wraps a response body so that:
//   - reads are bounded by an io.LimitReader (defense-in-depth body cap)
//   - the latency histogram is observed exactly once when Close is called,
//     mirroring the pre-migration "observe after full body read" semantics
type timedLimitedReadCloser struct {
	r       io.Reader
	c       io.Closer
	start   time.Time
	observe func(time.Time)
	once    sync.Once
}

func (t *timedLimitedReadCloser) Read(p []byte) (int, error) {
	return t.r.Read(p)
}

func (t *timedLimitedReadCloser) Close() error {
	t.once.Do(func() { t.observe(t.start) })
	return t.c.Close()
}
