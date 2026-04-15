package shared

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

var ntfyHTTPClient = &http.Client{Timeout: 10 * time.Second}

// NtfyPublisher sends notifications to an ntfy server.
type NtfyPublisher struct {
	URL   string
	Topic string
	Token string
}

func (n *NtfyPublisher) Name() string { return "ntfy" }

// maxNtfyBodyBytes is the maximum message body size before ntfy converts it to
// an attachment. We truncate to stay under this limit for inline display.
const maxNtfyBodyBytes = 4096

// ntfyRetryDelays controls the wait between publish attempts. Three attempts
// total: one initial try plus one retry after each delay.
var ntfyRetryDelays = []time.Duration{2 * time.Second, 5 * time.Second}

func (n *NtfyPublisher) Publish(ctx context.Context, title, priority, body string) error {
	body = Truncate(body, maxNtfyBodyBytes)
	ntfyURL := fmt.Sprintf("%s/%s", n.URL, n.Topic)

	var lastErr error
	for attempt := 0; attempt <= len(ntfyRetryDelays); attempt++ {
		if attempt > 0 {
			delay := ntfyRetryDelays[attempt-1]
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
			slog.Warn("retrying ntfy publish", "attempt", attempt+1, "after", delay)
		}

		req, err := http.NewRequestWithContext(ctx, "POST", ntfyURL, strings.NewReader(body))
		if err != nil {
			return fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Title", title)
		req.Header.Set("Priority", priority)
		req.Header.Set("Tags", "robot,mag")
		req.Header.Set("Markdown", "yes")
		if n.Token != "" {
			req.Header.Set("Authorization", "Bearer "+n.Token)
		}

		resp, err := ntfyHTTPClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("publish: %w", err)
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 500 {
			// Server error — worth retrying.
			lastErr = fmt.Errorf("ntfy returned %d", resp.StatusCode)
			continue
		}
		if resp.StatusCode >= 300 {
			// Client error (4xx) — retrying won't help.
			return fmt.Errorf("ntfy returned %d", resp.StatusCode)
		}
		return nil
	}
	return lastErr
}

// PublishAll sends to all publishers, logging errors. Returns the first error encountered.
func PublishAll(ctx context.Context, publishers []Publisher, title, priority, body string) error {
	var firstErr error
	for _, p := range publishers {
		if err := p.Publish(ctx, title, priority, body); err != nil {
			slog.Error("publish failed", "publisher", p.Name(), "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}
