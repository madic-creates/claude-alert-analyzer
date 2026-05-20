package shared

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// ClaudeClient wraps the Anthropic SDK with per-call model selection,
// 3-breakpoint prompt-cache plumbing, token-usage recording, and a forced
// summary turn at the end of an exhausted tool loop.
type ClaudeClient struct {
	sdk     *anthropic.Client
	Model   string
	metrics *AlertMetrics // nil/empty in tests that do not assert metrics
}

// NewClaudeClient wires the SDK against transport (body-size capping and
// latency-histogram observation). Auth options are passed only when the
// corresponding field is non-empty; main.go is the single source of truth
// (reads exactly one of ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN and, in
// T6/T7, unsets all ANTHROPIC_* env vars so the SDK has no env-var fallback).
func NewClaudeClient(cfg BaseConfig, transport http.RoundTripper) *ClaudeClient {
	httpClient := &http.Client{Timeout: 120 * time.Second, Transport: transport}
	opts := []option.RequestOption{option.WithHTTPClient(httpClient), option.WithMaxRetries(2)}
	if cfg.APIKey != "" {
		opts = append(opts, option.WithAPIKey(cfg.APIKey))
	}
	if cfg.AuthToken != "" {
		opts = append(opts, option.WithAuthToken(cfg.AuthToken))
	}
	if cfg.APIBaseURL != "" {
		opts = append(opts, option.WithBaseURL(cfg.APIBaseURL))
	}
	sdk := anthropic.NewClient(opts...)
	return &ClaudeClient{sdk: &sdk, Model: cfg.ClaudeModel}
}

// WithPrometheusMetrics attaches the AlertMetrics for token-usage recording.
func (c *ClaudeClient) WithPrometheusMetrics(m *AlertMetrics) *ClaudeClient {
	c.metrics = m
	return c
}

// systemBlocks builds the system field with a cache_control breakpoint (#1).
func systemBlocks(prompt string) []anthropic.TextBlockParam {
	return []anthropic.TextBlockParam{{Text: prompt, CacheControl: anthropic.NewCacheControlEphemeralParam()}}
}

// toolsWithCachedTail copies tools and adds cache_control to the last OfTool (#2).
func toolsWithCachedTail(tools []anthropic.ToolUnionParam) []anthropic.ToolUnionParam {
	if len(tools) == 0 {
		return tools
	}
	out := make([]anthropic.ToolUnionParam, len(tools))
	copy(out, tools)
	last := &out[len(out)-1]
	if last.OfTool != nil {
		toolCopy := *last.OfTool
		toolCopy.CacheControl = anthropic.NewCacheControlEphemeralParam()
		last.OfTool = &toolCopy
	}
	return out
}

// extractText concatenates all text blocks in a Claude response message.
func extractText(msg *anthropic.Message) string {
	var parts []string
	for _, b := range msg.Content {
		if tb, ok := b.AsAny().(anthropic.TextBlock); ok && tb.Text != "" {
			parts = append(parts, tb.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// Analyze sends a single-turn analysis request. severity threads through to
// token-usage recording. If model is empty, c.Model is used.
func (c *ClaudeClient) Analyze(ctx context.Context, severity Severity,
	model, systemPrompt, userPrompt string) (string, error) {
	if model == "" {
		model = c.Model
	}

	msg, err := c.sdk.Messages.New(ctx, anthropic.MessageNewParams{
		Model: anthropic.Model(model), MaxTokens: 2048, System: systemBlocks(systemPrompt),
		Messages: []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock(userPrompt))},
	})
	if err != nil {
		return "", err
	}

	slog.Info("Claude analysis complete", "model", model,
		"inputTokens", msg.Usage.InputTokens, "outputTokens", msg.Usage.OutputTokens,
		"cacheCreationTokens", msg.Usage.CacheCreationInputTokens,
		"cacheReadTokens", msg.Usage.CacheReadInputTokens)

	c.metrics.RecordClaudeUsage(severity, model,
		int(msg.Usage.InputTokens), int(msg.Usage.OutputTokens),
		int(msg.Usage.CacheCreationInputTokens), int(msg.Usage.CacheReadInputTokens))
	if msg.StopReason != "" && msg.StopReason != anthropic.StopReasonEndTurn {
		slog.Warn("analysis response may be truncated", "stop_reason", string(msg.StopReason),
			"model", model, "outputTokens", msg.Usage.OutputTokens)
	}
	return extractText(msg), nil
}

// appendToolResultsAndCacheTail appends a user message of tool_result blocks
// with cache_control on the last one (sliding breakpoint #3).
//
// Before marking the new tail, all cache_control breakpoints from prior
// tool_result blocks in the conversation are cleared. Anthropic's hosted API
// silently ages out older breakpoints (budget: 4), but some providers —
// notably Amazon Bedrock via OpenRouter — enforce a hard limit and return
// HTTP 400 when more than 4 blocks carry cache_control. Clearing stale
// breakpoints keeps the total at system(1) + tools(1) + current(1) = 3,
// compatible with all providers and semantically equivalent (the latest
// breakpoint always covers the full conversation prefix).
func appendToolResultsAndCacheTail(messages []anthropic.MessageParam, results []anthropic.ContentBlockParamUnion) []anthropic.MessageParam {
	if len(results) == 0 {
		return messages
	}
	for i := range messages {
		if messages[i].Role != anthropic.MessageParamRoleUser {
			continue
		}
		for j := range messages[i].Content {
			if messages[i].Content[j].OfToolResult != nil {
				trCopy := *messages[i].Content[j].OfToolResult
				trCopy.CacheControl = anthropic.CacheControlEphemeralParam{} // zero = omitzero → not serialised
				messages[i].Content[j].OfToolResult = &trCopy
			}
		}
	}
	last := &results[len(results)-1]
	if last.OfToolResult != nil {
		trCopy := *last.OfToolResult
		trCopy.CacheControl = anthropic.NewCacheControlEphemeralParam()
		last.OfToolResult = &trCopy
	}
	return append(messages, anthropic.MessageParam{Role: anthropic.MessageParamRoleUser, Content: results})
}

// RunToolLoop runs a multi-turn Claude conversation with tool use. After
// maxRounds of tool calls, a final tool-less request forces a text response.
// severity threads through to token-usage recording.
// maxRounds must be at least 1; 0 or negative returns an error immediately.
func (c *ClaudeClient) RunToolLoop(ctx context.Context, severity Severity,
	model, systemPrompt, userPrompt string,
	tools []anthropic.ToolUnionParam, maxRounds int,
	handleTool func(name string, input json.RawMessage) (string, error),
) (string, int, bool, error) {
	if model == "" {
		model = c.Model
	}
	if maxRounds <= 0 {
		return "", 0, false, fmt.Errorf("maxRounds must be at least 1, got %d", maxRounds)
	}

	messages := []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock(userPrompt))}

	var totalInput, totalOutput, totalCacheCreation, totalCacheRead int64
	defer func() {
		c.metrics.RecordClaudeUsage(severity, model,
			int(totalInput), int(totalOutput), int(totalCacheCreation), int(totalCacheRead))
	}()

	for round := range maxRounds {
		slog.Info("tool loop round", "round", round+1, "maxRounds", maxRounds)

		msg, err := c.sdk.Messages.New(ctx, anthropic.MessageNewParams{
			Model: anthropic.Model(model), MaxTokens: 4096, System: systemBlocks(systemPrompt),
			Tools: toolsWithCachedTail(tools), Messages: messages,
		})
		if err != nil {
			return "", round + 1, false, fmt.Errorf("round %d: %w", round+1, err)
		}

		totalInput += msg.Usage.InputTokens
		totalOutput += msg.Usage.OutputTokens
		totalCacheCreation += msg.Usage.CacheCreationInputTokens
		totalCacheRead += msg.Usage.CacheReadInputTokens
		messages = append(messages, msg.ToParam())

		if msg.StopReason == anthropic.StopReasonEndTurn {
			slog.Info("tool loop complete", "rounds", round+1,
				"totalInputTokens", totalInput, "totalOutputTokens", totalOutput,
				"totalCacheCreationTokens", totalCacheCreation,
				"totalCacheReadTokens", totalCacheRead)
			return extractText(msg), round + 1, false, nil
		}

		var toolResults []anthropic.ContentBlockParamUnion
		for _, block := range msg.Content {
			tu, ok := block.AsAny().(anthropic.ToolUseBlock)
			if !ok {
				continue
			}
			slog.Info("tool call", "round", round+1, "tool", tu.Name, "id", tu.ID)
			output, err := handleTool(tu.Name, tu.Input)
			isError := err != nil
			if isError {
				output = fmt.Sprintf("error: %v", err)
			}
			toolResults = append(toolResults, anthropic.NewToolResultBlock(tu.ID, output, isError))
		}

		// No tool_use blocks: treat as final answer (covers stop_reason=max_tokens).
		if len(toolResults) == 0 {
			slog.Warn("tool loop: no tool_use blocks, returning text as final answer",
				"stop_reason", string(msg.StopReason), "round", round+1)
			return extractText(msg), round + 1, false, nil
		}
		messages = appendToolResultsAndCacheTail(messages, toolResults)
	}

	// Max rounds reached — append summary text to the last (user) message
	// to preserve role alternation, then issue the tool-less summary call.
	slog.Info("tool loop max rounds reached, requesting summary", "maxRounds", maxRounds)
	const summaryPrompt = "You have reached the maximum number of diagnostic rounds. Do NOT call any more tools. Provide your final analysis now based on all information gathered so far. Start directly with the analysis — no preamble or meta-commentary."
	appendTextToLastUserMessage(messages, summaryPrompt)
	analysis, err := c.runForcedSummary(ctx, model, systemPrompt, tools, messages,
		&totalInput, &totalOutput, &totalCacheCreation, &totalCacheRead)
	return analysis, maxRounds, true, err
}

// runForcedSummary issues the final tool-less request after max rounds.
func (c *ClaudeClient) runForcedSummary(ctx context.Context, model, systemPrompt string,
	tools []anthropic.ToolUnionParam, messages []anthropic.MessageParam,
	totalInput, totalOutput, totalCacheCreation, totalCacheRead *int64,
) (string, error) {
	msg, err := c.sdk.Messages.New(ctx, anthropic.MessageNewParams{
		Model: anthropic.Model(model), MaxTokens: 4096, System: systemBlocks(systemPrompt),
		Tools:      toolsWithCachedTail(tools),
		ToolChoice: anthropic.ToolChoiceUnionParam{OfNone: &anthropic.ToolChoiceNoneParam{}},
		Messages:   messages,
	})
	if err != nil {
		return "", fmt.Errorf("summary: %w", err)
	}

	*totalInput += msg.Usage.InputTokens
	*totalOutput += msg.Usage.OutputTokens
	*totalCacheCreation += msg.Usage.CacheCreationInputTokens
	*totalCacheRead += msg.Usage.CacheReadInputTokens
	analysis := extractText(msg)
	slog.Info("tool loop complete (forced summary)", "totalInputTokens", *totalInput,
		"totalOutputTokens", *totalOutput,
		"totalCacheCreationTokens", *totalCacheCreation,
		"totalCacheReadTokens", *totalCacheRead,
		"analysisLen", len(analysis))
	if msg.StopReason != "" && msg.StopReason != anthropic.StopReasonEndTurn {
		slog.Warn("forced summary response may be truncated", "stop_reason", string(msg.StopReason),
			"model", model, "outputTokens", msg.Usage.OutputTokens)
	}
	if len(analysis) == 0 {
		slog.Warn("forced summary produced empty analysis", "contentBlocks", len(msg.Content))
	}
	return analysis, nil
}

// appendTextToLastUserMessage appends a text block to the last (user) message.
// Panics on invariant violations (empty slice or wrong role) — these represent
// internal bugs in the tool loop, never recoverable user errors. The pipeline's
// panic-recovery defer catches and logs any such panic.
func appendTextToLastUserMessage(messages []anthropic.MessageParam, text string) {
	if len(messages) == 0 {
		panic("internal: messages slice is empty when appending forced-summary text")
	}
	last := &messages[len(messages)-1]
	if last.Role != anthropic.MessageParamRoleUser {
		panic(fmt.Sprintf("internal: last message role is %q, expected user", string(last.Role)))
	}
	last.Content = append(last.Content, anthropic.NewTextBlock(text))
}
