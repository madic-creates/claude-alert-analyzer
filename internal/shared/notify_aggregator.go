package shared

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// notifyAggregatorBufferSize is the size of the in-channel between Add() and
// the owner goroutine. Sized to absorb short bursts (~100 alerts in a single
// scrape interval) without dropping. Drops past this threshold are visible
// via the drops counter — the contract on Add() is non-blocking by design.
const notifyAggregatorBufferSize = 100

// NotifyAggregator buffers alert titles during a time interval and emits one
// summary notification per interval. It is concurrency-safe via a single
// owner goroutine that owns buffer + timer; Add() and Stop() communicate
// with the owner only via channels.
//
// Stop() uses a request/reply protocol with sync.Once so multiple callers
// receive the same result and the owner goroutine cannot leak.
type NotifyAggregator struct {
	publishers []Publisher
	interval   time.Duration
	titleFmt   string
	priority   string
	drops      prometheus.Counter

	in       chan string
	stopReq  chan stopRequest
	stopOnce sync.Once
	stopped  chan struct{}
	stopErr  error

	// stopping is set by the owner goroutine when it begins shutdown drain.
	// Add() callers check it FIRST so they drop instead of racing with the
	// owner's drain loop. Without this flag, an Add() that wins the random
	// select against the channel-full default could land an item in a.in
	// AFTER the owner has already drained-and-flushed → silently lost item.
	stopping atomic.Bool
}

type stopRequest struct {
	ctx context.Context
	ack chan error
}

// NewNotifyAggregator constructs the aggregator and spawns the owner goroutine.
// Returns nil if publishers is empty or interval <= 0.
func NewNotifyAggregator(publishers []Publisher, interval time.Duration, titleFmt, priority string, drops prometheus.Counter) *NotifyAggregator {
	if len(publishers) == 0 || interval <= 0 {
		return nil
	}
	a := &NotifyAggregator{
		publishers: publishers,
		interval:   interval,
		titleFmt:   titleFmt,
		priority:   priority,
		drops:      drops,
		in:         make(chan string, notifyAggregatorBufferSize),
		stopReq:    make(chan stopRequest, 1),
		stopped:    make(chan struct{}),
	}
	go a.run()
	return a
}

// Add buffers an alert title for the next aggregated notification.
// Returns false if stopped or the channel is full; both cases increment drops.
//
// Non-blocking by design: if the in-channel is at capacity, the alert is
// dropped (recorded in the drops counter) rather than blocking the caller.
// This keeps webhook-handler latency bounded under storm bursts. Operators
// monitoring the drops counter learn whether the configured buffer
// (notifyAggregatorBufferSize) is large enough for their alert volume.
//
// Drop ordering: the stopping flag is checked FIRST so Add() refuses sends
// once the owner has begun shutdown drain. Without this, a select-race
// between `a.in <- alertTitle` and `<-a.stopped` could land an item in
// the channel after the owner already drained-and-flushed → silent loss.
func (a *NotifyAggregator) Add(alertTitle string) bool {
	if a == nil {
		return false
	}
	if a.stopping.Load() {
		a.recordDrop()
		return false
	}
	select {
	case <-a.stopped:
		a.recordDrop()
		return false
	default:
	}
	select {
	case a.in <- alertTitle:
		return true
	case <-a.stopped:
		a.recordDrop()
		return false
	default:
		a.recordDrop()
		return false
	}
}

func (a *NotifyAggregator) recordDrop() {
	if a.drops != nil {
		a.drops.Inc()
	}
}

// Stop signals the owner goroutine to flush pending alerts and exit.
// Idempotent via sync.Once. Final flush uses caller-supplied ctx.
//
// Memory-model note: stopErr is read after stopOnce.Do returns. Per Go's
// sync.Once docs, "no call to Do returns until the one call to f returns" —
// so all callers (including those for whom Do is a no-op) observe the
// happens-before edge from the first caller's f-body, and the read of
// stopErr is race-free without an additional mutex.
func (a *NotifyAggregator) Stop(ctx context.Context) error {
	if a == nil {
		return nil
	}
	a.stopOnce.Do(func() {
		ack := make(chan error, 1)
		// stopReq has buffer 1 and stopOnce guarantees this is the sole writer,
		// so the send always completes immediately without blocking.
		a.stopReq <- stopRequest{ctx: ctx, ack: ack}
		select {
		case a.stopErr = <-ack:
		case <-ctx.Done():
			a.stopErr = ctx.Err()
		}
	})
	select {
	case <-a.stopped:
	case <-ctx.Done():
		return ctx.Err()
	}
	return a.stopErr
}

func (a *NotifyAggregator) run() {
	defer close(a.stopped)
	var buffer []string
	var timer *time.Timer

	flush := func(ctx context.Context) error {
		if len(buffer) == 0 {
			return nil
		}
		title := fmt.Sprintf(a.titleFmt, len(buffer))
		body := strings.Join(buffer, "\n")
		err := PublishAll(ctx, a.publishers, title, a.priority, body)
		// Drops invariant: every alert that enters Add() and is not eventually
		// surfaced in a notification must be reflected in the drops counter.
		// PublishAll-failure means the buffered titles never reach the operator,
		// so we count them here; channel-full and post-Stop drops are counted
		// in Add() itself.
		if err != nil && a.drops != nil {
			a.drops.Add(float64(len(buffer)))
		}
		buffer = nil
		return err
	}

	for {
		var timerC <-chan time.Time
		if timer != nil {
			timerC = timer.C
		}

		select {
		case alertTitle := <-a.in:
			buffer = append(buffer, alertTitle)
			if timer == nil {
				timer = time.NewTimer(a.interval)
			}
		case <-timerC:
			timer = nil
			if err := flush(context.Background()); err != nil {
				slog.Warn("aggregator tick flush failed", "error", err)
			}
		case req := <-a.stopReq:
			if timer != nil {
				timer.Stop()
			}
			// Signal Add() callers to start dropping. Any Add() that has already
			// passed the stopping-check but not yet sent into a.in is in a small
			// race window — the rolling-deadline drain below absorbs those.
			a.stopping.Store(true)
			drainDeadline := time.NewTimer(10 * time.Millisecond)
		drain:
			for {
				select {
				case alertTitle := <-a.in:
					buffer = append(buffer, alertTitle)
					if !drainDeadline.Stop() {
						<-drainDeadline.C
					}
					drainDeadline.Reset(10 * time.Millisecond)
				case <-drainDeadline.C:
					break drain
				}
			}
			drainDeadline.Stop()
			req.ack <- flush(req.ctx)
			return
		}
	}
}
