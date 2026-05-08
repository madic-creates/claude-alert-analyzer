package shared

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

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
		in:         make(chan string, 100),
		stopReq:    make(chan stopRequest, 1),
		stopped:    make(chan struct{}),
	}
	go a.run()
	return a
}

// Add buffers an alert title for the next aggregated notification.
// Returns false if stopped or the channel is full; both cases increment drops.
func (a *NotifyAggregator) Add(alertTitle string) bool {
	if a == nil {
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
func (a *NotifyAggregator) Stop(ctx context.Context) error {
	if a == nil {
		return nil
	}
	a.stopOnce.Do(func() {
		ack := make(chan error, 1)
		select {
		case a.stopReq <- stopRequest{ctx: ctx, ack: ack}:
			select {
			case a.stopErr = <-ack:
			case <-ctx.Done():
				a.stopErr = ctx.Err()
			}
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
		drain:
			for {
				select {
				case alertTitle := <-a.in:
					buffer = append(buffer, alertTitle)
				default:
					break drain
				}
			}
			req.ack <- flush(req.ctx)
			return
		}
	}
}
