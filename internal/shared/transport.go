package shared

import (
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// MaxResponseBytes bounds the amount of data read from an API response body
// to prevent a malicious or buggy upstream from exhausting memory.
const MaxResponseBytes = 2 * 1024 * 1024 // 2 MiB

// MaxBodyDrainBytes bounds how much of a non-success response body is drained
// to io.Discard before Close so Go's HTTP transport can return the connection
// to the pool for reuse. Set to 64 KiB so realistic upstream error responses
// — including HTML error pages emitted by reverse proxies (nginx, Cloudflare,
// AWS ALB) that wrap the real service — are fully consumed. The previous 4 KiB
// cap silently defeated connection reuse whenever an intermediate proxy
// returned a larger error page, forcing a new TCP (and TLS) handshake on every
// retry. The cap still bounds time spent reading from a hostile or
// pathologically slow server; combined with the per-request HTTP client
// timeout, total drain cost stays bounded.
const MaxBodyDrainBytes = 64 * 1024 // 64 KiB

// LimitedTransport wraps an http.RoundTripper to (a) cap response body size at
// MaxResponseBytes and (b) observe round-trip latency in a Prometheus histogram
// when the body is closed.
type LimitedTransport struct {
	inner             http.RoundTripper
	durationHistogram prometheus.Observer // optional; nil = no observation
	retryCounter      prometheus.Counter  // optional; nil = no retry counting
}

// NewLimitedTransport returns a LimitedTransport around inner. inner=nil falls
// back to http.DefaultTransport. hist=nil disables histogram observation.
func NewLimitedTransport(inner http.RoundTripper, hist prometheus.Observer) *LimitedTransport {
	if inner == nil {
		inner = http.DefaultTransport
	}
	return &LimitedTransport{
		inner:             inner,
		durationHistogram: hist,
	}
}

// WithRetryCounter attaches a counter incremented once per retried request
// attempt. Retries are detected via the X-Stainless-Retry-Count header the
// anthropic-sdk-go sets on every attempt ("0" on the first try). The SDK
// omits the header when the caller overrides default headers; in that case
// retries simply go uncounted — the transport never blocks a request over it.
func (lt *LimitedTransport) WithRetryCounter(c prometheus.Counter) *LimitedTransport {
	lt.retryCounter = c
	return lt
}

func (lt *LimitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	if c := req.Header.Get("X-Stainless-Retry-Count"); c != "" && c != "0" {
		if lt.retryCounter != nil {
			lt.retryCounter.Inc()
		}
		slog.Debug("Claude API request retried", "attempt", c,
			"method", req.Method, "host", req.URL.Host)
	}
	resp, err := lt.inner.RoundTrip(req)
	if err != nil {
		lt.observe(start)
		return nil, err
	}
	resp.Body = &timedLimitedReadCloser{
		r:       io.LimitReader(resp.Body, MaxResponseBytes),
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
