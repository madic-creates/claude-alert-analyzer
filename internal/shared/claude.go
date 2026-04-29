package shared

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const anthropicVersion = "2023-06-01"

// MaxResponseBytes bounds the amount of data read from an API response body
// to prevent a malicious or buggy upstream from exhausting memory.
const MaxResponseBytes = 2 * 1024 * 1024 // 2 MiB

// defaultRetryDelays are the wait durations before each retry attempt for
// transient API errors (429, 5xx). Two retries with 2 s and 4 s backoff give
// a short grace period for transient blips while keeping total worst-case wait
// well under the 120 s HTTP client timeout.
var defaultRetryDelays = []time.Duration{2 * time.Second, 4 * time.Second}

// isTransientStatus reports whether an HTTP status code indicates a transient
// server-side condition worth retrying. 429 Too Many Requests and 5xx server
// errors are retried. 4xx client errors (except 429) are permanent — retrying
// them wastes quota and adds latency without any chance of success.
func isTransientStatus(code int) bool {
	return code == http.StatusTooManyRequests || (code >= 500 && code < 600)
}

// ClaudeClient holds the HTTP client and configuration needed
// to talk to the Claude Messages API. It implements both Analyzer
// and ToolLoopRunner.
type ClaudeClient struct {
	HTTP    *http.Client
	BaseURL string
	APIKey  string
	Model   string

	// retryDelays controls the wait before each retry attempt for transient
	// API errors (429, 5xx). When nil, defaultRetryDelays is used. Set to
	// []time.Duration{} to disable retries (useful in tests).
	retryDelays []time.Duration

	// durationHistogram records Claude API call latency. May be nil.
	durationHistogram prometheus.Observer
}

// NewClaudeClient creates a ClaudeClient from a BaseConfig with a
// default 120-second timeout HTTP client.
func NewClaudeClient(cfg BaseConfig) *ClaudeClient {
	return &ClaudeClient{
		HTTP:    &http.Client{Timeout: 120 * time.Second},
		BaseURL: cfg.APIBaseURL,
		APIKey:  cfg.APIKey,
		Model:   cfg.ClaudeModel,
	}
}

// WithPrometheusMetrics attaches Prometheus observers to the client so that
// each API call is timed. Call this after NewClaudeClient.
func (c *ClaudeClient) WithPrometheusMetrics(m *AlertMetrics, source string) *ClaudeClient {
	if m != nil && m.Prom != nil {
		c.durationHistogram = m.Prom.ClaudeAPIDuration.WithLabelValues(source)
	}
	return c
}

// sendRequest sends a JSON body to the Claude API and returns the raw response
// bytes. Transient errors (429, 5xx, network failures) are retried with
// exponential backoff using c.retryDelays (defaultRetryDelays when nil).
// Each HTTP round-trip is timed and recorded in durationHistogram.
func (c *ClaudeClient) sendRequest(ctx context.Context, body any) ([]byte, error) {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	delays := c.retryDelays
	if delays == nil {
		delays = defaultRetryDelays
	}
	maxAttempts := len(delays) + 1

	var lastErr error
	for attempt := range maxAttempts {
		if attempt > 0 {
			delay := delays[attempt-1]
			slog.Info("retrying Claude API request",
				"attempt", attempt+1, "maxAttempts", maxAttempts, "delay", delay)
			if delay > 0 {
				retryTimer := time.NewTimer(delay)
				select {
				case <-ctx.Done():
					retryTimer.Stop()
					return nil, fmt.Errorf("context cancelled awaiting retry: %w", ctx.Err())
				case <-retryTimer.C:
				}
			}
		}

		req, reqErr := http.NewRequestWithContext(ctx, "POST", c.BaseURL, bytes.NewReader(bodyBytes))
		if reqErr != nil {
			return nil, fmt.Errorf("create request: %w", reqErr)
		}
		req.Header.Set("Content-Type", "application/json")
		if isAnthropicURL(c.BaseURL) {
			req.Header.Set("x-api-key", c.APIKey)
			req.Header.Set("anthropic-version", anthropicVersion)
		} else {
			req.Header.Set("Authorization", "Bearer "+c.APIKey)
		}

		start := time.Now()
		resp, doErr := c.HTTP.Do(req)
		if doErr != nil {
			// Network error: potentially transient. Do not retry when the
			// context is already done — the error is caused by the
			// cancellation itself, not a server-side failure.
			lastErr = fmt.Errorf("API request: %w", doErr)
			if ctx.Err() != nil {
				return nil, lastErr
			}
			continue
		}

		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes))
		_ = resp.Body.Close()
		if readErr != nil {
			// Body read failed: potentially transient (connection drop mid-response).
			// Do not retry when the context is already done — the read failure is
			// caused by the cancellation itself, not a server-side failure. This
			// mirrors the same ctx.Err() guard applied to doErr above.
			lastErr = fmt.Errorf("read response: %w", readErr)
			if ctx.Err() != nil {
				return nil, lastErr
			}
			continue
		}

		// Record full round-trip latency per attempt (after body read, not just
		// header receipt). Recording on every attempt — including failed ones —
		// lets operators see retry latency and correlate error spikes with
		// latency changes (e.g. a fast 429 vs a slow 500).
		if c.durationHistogram != nil {
			c.durationHistogram.Observe(time.Since(start).Seconds())
		}

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("API returned %d: %s", resp.StatusCode, Truncate(RedactSecrets(string(respBody)), 300))
			if isTransientStatus(resp.StatusCode) {
				continue
			}
			return nil, lastErr
		}

		return respBody, nil
	}

	return nil, lastErr
}

// Analyze sends a single-turn analysis request to the Claude API.
func (c *ClaudeClient) Analyze(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	reqBody := ToolRequest{
		Model:     c.Model,
		MaxTokens: 2048,
		System:    systemPrompt,
		Messages:  []ToolMessage{{Role: "user", Content: userPrompt}},
	}

	respBody, err := c.sendRequest(ctx, reqBody)
	if err != nil {
		return "", err
	}

	var result ToolResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}

	if result.Error != nil {
		return "", fmt.Errorf("API error: %s: %s", result.Error.Type, result.Error.Message)
	}

	slog.Info("Claude analysis complete",
		"model", c.Model,
		"inputTokens", result.Usage.InputTokens,
		"outputTokens", result.Usage.OutputTokens)

	// Warn when the API signals that the response was cut off before a natural
	// stopping point. "end_turn" is the normal stop reason; anything else
	// (typically "max_tokens") means the output was truncated by the token
	// budget and the published analysis may end mid-sentence. This mirrors the
	// slog.Warn already emitted by RunToolLoop for its non-"end_turn" early
	// returns and makes truncated single-turn analyses visible in operator logs.
	if result.StopReason != "" && result.StopReason != "end_turn" {
		slog.Warn("analysis response may be truncated",
			"stop_reason", result.StopReason,
			"model", c.Model,
			"outputTokens", result.Usage.OutputTokens)
	}

	return extractText(result.Content), nil
}

// RunToolLoop runs a multi-turn Claude conversation with tool use.
// handleTool is called for each tool_use block. After maxRounds of tool calls,
// a final request without tools forces Claude to produce a text response.
// maxRounds must be at least 1; passing 0 or negative returns an error
// immediately to prevent the forced-summary logic from constructing two
// consecutive user messages (which the Anthropic API rejects with 400
// "roles must alternate").
func (c *ClaudeClient) RunToolLoop(
	ctx context.Context,
	systemPrompt string,
	userPrompt string,
	tools []Tool,
	maxRounds int,
	handleTool func(name string, input json.RawMessage) (string, error),
) (string, error) {
	if maxRounds <= 0 {
		return "", fmt.Errorf("maxRounds must be at least 1, got %d", maxRounds)
	}
	messages := []ToolMessage{{Role: "user", Content: userPrompt}}

	var totalInput, totalOutput int

	for round := range maxRounds {
		slog.Info("tool loop round", "round", round+1, "maxRounds", maxRounds)

		reqBody := ToolRequest{
			Model:     c.Model,
			MaxTokens: 4096,
			System:    systemPrompt,
			Tools:     tools,
			Messages:  messages,
		}

		respBody, err := c.sendRequest(ctx, reqBody)
		if err != nil {
			return "", fmt.Errorf("round %d: %w", round+1, err)
		}

		var resp ToolResponse
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return "", fmt.Errorf("round %d parse: %w", round+1, err)
		}

		if resp.Error != nil {
			return "", fmt.Errorf("round %d API error: %s: %s", round+1, resp.Error.Type, resp.Error.Message)
		}

		totalInput += resp.Usage.InputTokens
		totalOutput += resp.Usage.OutputTokens

		// Append assistant response to conversation
		messages = append(messages, ToolMessage{Role: "assistant", Content: resp.Content})

		if resp.StopReason == "end_turn" {
			slog.Info("tool loop complete",
				"rounds", round+1,
				"totalInputTokens", totalInput,
				"totalOutputTokens", totalOutput)
			return extractText(resp.Content), nil
		}

		// Process tool calls
		var toolResults []ContentBlock
		for _, block := range resp.Content {
			if block.Type != "tool_use" {
				continue
			}

			slog.Info("tool call", "round", round+1, "tool", block.Name, "id", block.ID)
			output, err := handleTool(block.Name, block.Input)
			var isError bool
			if err != nil {
				output = fmt.Sprintf("error: %v", err)
				isError = true
			}

			toolResults = append(toolResults, ContentBlock{
				Type:      "tool_result",
				ToolUseID: block.ID,
				Content:   output,
				IsError:   isError,
			})
		}

		// No tool_use blocks in response — treat as final answer. This handles
		// "max_tokens" and other non-"end_turn" stop reasons that carry text but
		// no tool calls. Appending a nil tool_results slice would marshal to
		// "content": null and cause the next API call to fail with 400.
		if len(toolResults) == 0 {
			slog.Warn("tool loop: no tool_use blocks found, returning text as final answer",
				"stop_reason", resp.StopReason, "round", round+1)
			return extractText(resp.Content), nil
		}

		messages = append(messages, ToolMessage{Role: "user", Content: toolResults})
	}

	// Max rounds reached — append the summary prompt to the last user message (which
	// contains the final round's tool_result blocks) rather than starting a new user
	// turn. Creating a second consecutive user message would be rejected by the
	// Anthropic API with a 400 "roles must alternate" error. The API explicitly
	// supports mixing tool_result and text blocks in the same user message.
	slog.Info("tool loop max rounds reached, requesting summary", "maxRounds", maxRounds)

	const summaryPrompt = "You have reached the maximum number of diagnostic rounds. Do NOT call any more tools. Provide your final analysis now based on all information gathered so far. Start directly with the analysis — no preamble or meta-commentary."

	// Each iteration appends a ToolMessage{Role:"user", Content:[]ContentBlock{…}}
	// at the end of the for-loop body above, so by the time all rounds complete,
	// messages[lastIdx].Content is always a []ContentBlock. The type assertion
	// must therefore always succeed. A panic here would indicate a broken loop
	// invariant, making the bug immediately visible rather than silently
	// corrupting the conversation with two consecutive user messages.
	lastIdx := len(messages) - 1
	toolResults := messages[lastIdx].Content.([]ContentBlock)
	messages[lastIdx].Content = append(toolResults, ContentBlock{
		Type: "text",
		Text: summaryPrompt,
	})

	reqBody := ToolRequest{
		Model:      c.Model,
		MaxTokens:  4096,
		System:     systemPrompt,
		Tools:      tools,
		ToolChoice: &ToolChoice{Type: "none"}, // prevent tool calls in the forced-summary turn
		Messages:   messages,
	}

	respBody, err := c.sendRequest(ctx, reqBody)
	if err != nil {
		return "", fmt.Errorf("summary request: %w", err)
	}

	var resp ToolResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return "", fmt.Errorf("summary parse: %w", err)
	}

	if resp.Error != nil {
		return "", fmt.Errorf("summary API error: %s: %s", resp.Error.Type, resp.Error.Message)
	}

	totalInput += resp.Usage.InputTokens
	totalOutput += resp.Usage.OutputTokens

	analysis := extractText(resp.Content)

	slog.Info("tool loop complete (forced summary)",
		"totalRounds", maxRounds,
		"totalInputTokens", totalInput,
		"totalOutputTokens", totalOutput,
		"analysisLen", len(analysis))

	if len(analysis) == 0 {
		slog.Warn("forced summary produced empty analysis", "contentBlocks", len(resp.Content))
	}

	return analysis, nil
}

// isAnthropicURL returns true when rawURL targets the Anthropic API directly
// (host is exactly "anthropic.com" or a subdomain like "api.anthropic.com").
// Using net/url host parsing avoids false positives from substring matches
// on URLs like "https://anthropic.com.proxy.example.com".
func isAnthropicURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname()) // strips any :port suffix
	return host == "anthropic.com" || strings.HasSuffix(host, ".anthropic.com")
}

func extractText(blocks []ContentBlock) string {
	var parts []string
	for _, b := range blocks {
		if b.Type == "text" && b.Text != "" {
			parts = append(parts, b.Text)
		}
	}
	return strings.Join(parts, "\n")
}
