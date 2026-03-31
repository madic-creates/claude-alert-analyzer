package shared

import "context"

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

// ContextGatherer collects diagnostic context for a given alert.
type ContextGatherer interface {
	Gather(ctx context.Context, alert AlertPayload) (AnalysisContext, error)
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
	NtfyPublishURL   string
	NtfyPublishTopic string
	NtfyPublishToken string
	ClaudeModel      string
	CooldownSeconds  int
	Port             string
	WebhookSecret    string
	APIBaseURL       string
	APIKey           string
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
