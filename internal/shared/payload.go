package shared

import (
	"context"
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
	APIBaseURL      string // ANTHROPIC_BASE_URL
	APIKey          string // ANTHROPIC_API_KEY (sets x-api-key)
	AuthToken       string // ANTHROPIC_AUTH_TOKEN (sets Authorization: Bearer)
}
