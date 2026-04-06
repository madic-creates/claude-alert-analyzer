package shared

import (
	"context"
	"encoding/json"
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
	var s string
	for _, sec := range ac.Sections {
		s += "## " + sec.Name + "\n" + sec.Content + "\n\n"
	}
	return s
}

// Publisher sends analysis results to a notification target.
type Publisher interface {
	Publish(ctx context.Context, title, priority, body string) error
	Name() string
}

// AlertPayload is the common alert representation.
type AlertPayload struct {
	Fingerprint string
	Title       string
	Severity    string
	Source      string            // "k8s" or "checkmk"
	Fields      map[string]string // source-specific key-value pairs
}

// BaseConfig holds configuration shared by all analyzers.
type BaseConfig struct {
	ClaudeModel     string
	CooldownSeconds int
	Port            string
	WebhookSecret   string
	APIBaseURL      string
	APIKey          string
}

// ClaudeRequest is the Claude Messages API request body.
type ClaudeRequest struct {
	Model     string          `json:"model"`
	MaxTokens int             `json:"max_tokens"`
	System    string          `json:"system"`
	Messages  []ClaudeMessage `json:"messages"`
}

type ClaudeMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Tool-use types for agentic Claude interactions.

type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema InputSchema `json:"input_schema"`
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
	Type      string          `json:"type"`
	Text      string          `json:"text,omitempty"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Content   string          `json:"content,omitempty"`
}

// ToolMessage supports both string content (user/assistant text) and
// []ContentBlock content (tool_use responses, tool_result messages).
type ToolMessage struct {
	Role    string `json:"role"`
	Content any    `json:"content"` // string or []ContentBlock
}

// ToolRequest is the Claude Messages API request with tool support.
type ToolRequest struct {
	Model     string        `json:"model"`
	MaxTokens int           `json:"max_tokens"`
	System    string        `json:"system"`
	Tools     []Tool        `json:"tools,omitempty"`
	Messages  []ToolMessage `json:"messages"`
}

// ToolResponse is the Claude Messages API response with tool-use support.
type ToolResponse struct {
	Content    []ContentBlock `json:"content"`
	StopReason string         `json:"stop_reason"`
	Usage      struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// ClaudeResponse is the Claude Messages API response body.
type ClaudeResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text,omitempty"`
	} `json:"content"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}
