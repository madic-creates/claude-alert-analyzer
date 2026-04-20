package k8s

import (
	"time"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
)

// AlertmanagerWebhook is the Alertmanager webhook payload.
type AlertmanagerWebhook struct {
	Version           string            `json:"version"`
	GroupKey          string            `json:"groupKey"`
	Status            string            `json:"status"`
	Receiver          string            `json:"receiver"`
	GroupLabels       map[string]string `json:"groupLabels"`
	CommonLabels      map[string]string `json:"commonLabels"`
	CommonAnnotations map[string]string `json:"commonAnnotations"`
	ExternalURL       string            `json:"externalURL"`
	Alerts            []Alert           `json:"alerts"`
}

// Alert is a single alert from Alertmanager.
type Alert struct {
	Status       string            `json:"status"`
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	StartsAt     time.Time         `json:"startsAt"`
	EndsAt       time.Time         `json:"endsAt"`
	GeneratorURL string            `json:"generatorURL"`
	Fingerprint  string            `json:"fingerprint"`
}

// PromQueryResponse is the Prometheus /api/v1/query response.
type PromQueryResponse struct {
	Status    string `json:"status"`
	ErrorType string `json:"errorType"`
	Error     string `json:"error"`
	Data      struct {
		ResultType string       `json:"resultType"`
		Result     []PromResult `json:"result"`
	} `json:"data"`
}

// PromResult is a single result from a Prometheus query.
type PromResult struct {
	Metric map[string]string `json:"metric"`
	Value  [2]interface{}    `json:"value"`
}

// Config holds all configuration for the K8s alert analyzer.
type Config struct {
	PrometheusURL     string
	ClaudeModel       string
	CooldownSeconds   int
	SkipResolved      bool
	Port              string
	MetricsPort       string
	WebhookSecret     string
	AllowedNamespaces []string      // Namespace allowlist for log collection
	MaxLogBytes       int           // Per-pod log truncation limit
	APIBaseURL        string        // Claude API endpoint (supports Anthropic and OpenRouter)
	APIKey            string        // API key for authentication
	KubeAPITimeout    time.Duration // Timeout for Kubernetes API context gathering (0 = default 30s)
	PromTimeout       time.Duration // Timeout for Prometheus context gathering (0 = default 30s)
}

// BaseConfig returns a shared.BaseConfig derived from this Config.
func (c Config) BaseConfig() shared.BaseConfig {
	return shared.BaseConfig{
		ClaudeModel:     c.ClaudeModel,
		CooldownSeconds: c.CooldownSeconds,
		Port:            c.Port,
		MetricsPort:     c.MetricsPort,
		WebhookSecret:   c.WebhookSecret,
		APIBaseURL:      c.APIBaseURL,
		APIKey:          c.APIKey,
	}
}
