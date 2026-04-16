package shared

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const anthropicVersion = "2023-06-01"

// MaxResponseBytes bounds the amount of data read from an API response body
// to prevent a malicious or buggy upstream from exhausting memory.
const MaxResponseBytes = 2 * 1024 * 1024 // 2 MiB

// ClaudeClient holds the HTTP client and configuration needed
// to talk to the Claude Messages API. It implements both Analyzer
// and ToolLoopRunner.
type ClaudeClient struct {
	HTTP    *http.Client
	BaseURL string
	APIKey  string
	Model   string
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

// sendRequest sends a JSON body to the Claude API and returns the raw response bytes.
func (c *ClaudeClient) sendRequest(ctx context.Context, body any) ([]byte, error) {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	if strings.Contains(c.BaseURL, "anthropic.com") {
		req.Header.Set("x-api-key", c.APIKey)
		req.Header.Set("anthropic-version", anthropicVersion)
	} else {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned %d: %s", resp.StatusCode, Truncate(string(respBody), 300))
	}

	return respBody, nil
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

	return extractText(result.Content), nil
}

// RunToolLoop runs a multi-turn Claude conversation with tool use.
// handleTool is called for each tool_use block. After maxRounds of tool calls,
// a final request without tools forces Claude to produce a text response.
func (c *ClaudeClient) RunToolLoop(
	ctx context.Context,
	systemPrompt string,
	userPrompt string,
	tools []Tool,
	maxRounds int,
	handleTool func(name string, input json.RawMessage) (string, error),
) (string, error) {
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
			if err != nil {
				output = fmt.Sprintf("error: %v", err)
			}

			toolResults = append(toolResults, ContentBlock{
				Type:      "tool_result",
				ToolUseID: block.ID,
				Content:   output,
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

	// Max rounds reached — add explicit prompt and send with tools (required by API
	// when conversation contains tool_use blocks) to force a text summary.
	slog.Info("tool loop max rounds reached, requesting summary", "maxRounds", maxRounds)

	messages = append(messages, ToolMessage{
		Role:    "user",
		Content: "You have reached the maximum number of diagnostic rounds. Do NOT call any more tools. Provide your final analysis now based on all information gathered so far. Start directly with the analysis — no preamble or meta-commentary.",
	})

	reqBody := ToolRequest{
		Model:     c.Model,
		MaxTokens: 4096,
		System:    systemPrompt,
		Tools:     tools,
		Messages:  messages,
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

func extractText(blocks []ContentBlock) string {
	var parts []string
	for _, b := range blocks {
		if b.Type == "text" && b.Text != "" {
			parts = append(parts, b.Text)
		}
	}
	return strings.Join(parts, "\n")
}
