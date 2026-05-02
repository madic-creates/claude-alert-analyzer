package shared

import (
	"context"
	"encoding/json"
	"strings"
)

// AnalysisContext holds named text sections injected into the Claude user prompt.
type AnalysisContext struct {
	Sections []ContextSection
}

type ContextSection struct {
	Name    string
	Content string
}

// FormatForPrompt renders all sections as a single string for Claude.
func (ac AnalysisContext) FormatForPrompt() string {
	var b strings.Builder
	for _, sec := range ac.Sections {
		b.WriteString("## ")
		b.WriteString(sec.Name)
		b.WriteByte('\n')
		b.WriteString(sec.Content)
		b.WriteString("\n\n")
	}
	return b.String()
}

// Publisher sends analysis results to a notification target.
type Publisher interface {
	Publish(ctx context.Context, title, priority, body string) error
	Name() string
}

// AlertPayload is the common alert representation.
type AlertPayload struct {
	Fingerprint   string
	Title         string
	Severity      string            // free-form, used for ntfy display (preserved)
	SeverityLevel Severity          // normalized, used for AnalysisPolicy routing
	Source        string            // "k8s" or "checkmk"
	Fields        map[string]string // source-specific key-value pairs
}

// BaseConfig holds configuration shared by all analyzers.
type BaseConfig struct {
	ClaudeModel     string
	CooldownSeconds int
	Port            string
	MetricsPort     string
	WebhookSecret   string
	APIBaseURL      string
	APIKey          string
}

// Tool-use types for agentic Claude interactions.

// CacheControl marks a content block for prompt caching.
type CacheControl struct {
	Type string `json:"type"` // currently only "ephemeral"
}

// SystemBlock is one element of a structured system prompt; lets us attach
// cache_control to the tail of the static prompt for prompt caching.
type SystemBlock struct {
	Type         string        `json:"type"` // "text"
	Text         string        `json:"text"`
	CacheControl *CacheControl `json:"cache_control,omitempty"`
}

type Tool struct {
	Name         string        `json:"name"`
	Description  string        `json:"description"`
	InputSchema  InputSchema   `json:"input_schema"`
	CacheControl *CacheControl `json:"cache_control,omitempty"`
}

type InputSchema struct {
	Type       string              `json:"type"`
	Properties map[string]Property `json:"properties"`
	Required   []string            `json:"required"`
}

type Property struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Items       *Items `json:"items,omitempty"`
}

type Items struct {
	Type string `json:"type"`
}

type ContentBlock struct {
	Type         string          `json:"type"`
	Text         string          `json:"text,omitempty"`
	ID           string          `json:"id,omitempty"`
	Name         string          `json:"name,omitempty"`
	Input        json.RawMessage `json:"input,omitempty"`
	ToolUseID    string          `json:"tool_use_id,omitempty"`
	Content      string          `json:"content,omitempty"`
	IsError      bool            `json:"is_error,omitempty"`
	CacheControl *CacheControl   `json:"cache_control,omitempty"`
}

// ToolMessage supports both string content (user/assistant text) and
// []ContentBlock content (tool_use responses, tool_result messages).
type ToolMessage struct {
	Role    string `json:"role"`
	Content any    `json:"content"` // string or []ContentBlock
}

// ToolChoice controls which tool (if any) Claude may call.
// Use Type "none" to force a text-only response even when tools are present.
type ToolChoice struct {
	Type string `json:"type"`
}

// ToolRequest is the Claude Messages API request with tool support.
type ToolRequest struct {
	Model      string        `json:"model"`
	MaxTokens  int           `json:"max_tokens"`
	System     []SystemBlock `json:"system"`
	Tools      []Tool        `json:"tools,omitempty"`
	ToolChoice *ToolChoice   `json:"tool_choice,omitempty"`
	Messages   []ToolMessage `json:"messages"`
}

// ToolResponse is the Claude Messages API response with tool-use support.
type ToolResponse struct {
	Content    []ContentBlock `json:"content"`
	StopReason string         `json:"stop_reason"`
	Usage      struct {
		InputTokens              int `json:"input_tokens"`
		OutputTokens             int `json:"output_tokens"`
		CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
		CacheReadInputTokens     int `json:"cache_read_input_tokens"`
	} `json:"usage"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}
