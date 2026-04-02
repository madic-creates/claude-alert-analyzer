package shared

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var ntfyHTTPClient = &http.Client{Timeout: 10 * time.Second}

func PublishToNtfy(ctx context.Context, cfg BaseConfig, title, priority, analysis string) error {
	ntfyURL := fmt.Sprintf("%s/%s", cfg.NtfyPublishURL, cfg.NtfyPublishTopic)
	req, err := http.NewRequestWithContext(ctx, "POST", ntfyURL, strings.NewReader(analysis))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Title", title)
	req.Header.Set("Priority", priority)
	req.Header.Set("Tags", "robot,mag")
	req.Header.Set("Markdown", "yes")
	if cfg.NtfyPublishToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.NtfyPublishToken)
	}

	resp, err := ntfyHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("publish: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 300 {
		return fmt.Errorf("ntfy returned %d", resp.StatusCode)
	}
	return nil
}
