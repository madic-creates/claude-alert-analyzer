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

// DefaultNtfyRetryDelays controls the wait between publish attempts. Three
// attempts total: one initial try plus one retry after each delay.
var DefaultNtfyRetryDelays = []time.Duration{2 * time.Second, 5 * time.Second}

// NtfyPublisher sends notifications to an ntfy server.
type NtfyPublisher struct {
	HTTP        *http.Client
	URL         string
	Topic       string
	Token       string
	RetryDelays []time.Duration
}

// NewNtfyPublisher creates an NtfyPublisher with default HTTP client and retry delays.
func NewNtfyPublisher(url, topic, token string) *NtfyPublisher {
	return &NtfyPublisher{
		HTTP:        &http.Client{Timeout: 10 * time.Second},
		URL:         url,
		Topic:       topic,
		Token:       token,
		RetryDelays: DefaultNtfyRetryDelays,
	}
}

func (n *NtfyPublisher) Name() string { return "ntfy" }

// maxNtfyBodyBytes is the maximum message body size before ntfy converts it to
// an attachment. We truncate to stay under this limit for inline display.
const maxNtfyBodyBytes = 4096

// maxNtfyTitleBytes is the maximum title length accepted by the ntfy server.
// ntfy enforces this limit server-side and returns 400 Bad Request if exceeded.
// Without client-side truncation, alerts with long hostnames or service names
// would fail every publish attempt and never deliver a notification.
const maxNtfyTitleBytes = 250

func (n *NtfyPublisher) Publish(ctx context.Context, title, priority, body string) error {
	body = Truncate(body, maxNtfyBodyBytes)
	if len(title) > maxNtfyTitleBytes {
		// Trim to a valid UTF-8 boundary and append "..." to signal truncation.
		// We use a plain ellipsis rather than truncationMarker because titles
		// are single-line HTTP headers and must not contain newlines.
		cutAt := maxNtfyTitleBytes - 3 // reserve 3 bytes for "..."
		title = strings.ToValidUTF8(title[:cutAt], "") + "..."
	}
	ntfyURL := fmt.Sprintf("%s/%s", n.URL, n.Topic)

	retryDelays := n.RetryDelays
	if retryDelays == nil {
		retryDelays = DefaultNtfyRetryDelays
	}

	var lastErr error
	for attempt := 0; attempt <= len(retryDelays); attempt++ {
		if attempt > 0 {
			delay := retryDelays[attempt-1]
			// Use time.NewTimer instead of time.After so we can Stop() it when
			// the context is cancelled. time.After leaks the underlying timer
			// until it fires; with retry delays up to several seconds this can
			// accumulate during graceful shutdown where many in-flight publishes
			// are cancelled simultaneously.
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
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

		resp, err := n.HTTP.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("publish: %w", err)
			continue
		}
		respSnippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		_ = resp.Body.Close()

		if resp.StatusCode >= 500 {
			// Server error — worth retrying.
			lastErr = fmt.Errorf("ntfy returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respSnippet)))
			continue
		}
		if resp.StatusCode >= 300 {
			// Client error (4xx) — retrying won't help.
			return fmt.Errorf("ntfy returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respSnippet)))
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
