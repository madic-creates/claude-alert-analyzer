package k8s

import (
	"net/http"
	"testing"
	"time"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
)

// TestNewPrometheusClient_FieldFromURL verifies that NewPrometheusClient stores
// the supplied URL.
func TestNewPrometheusClient_FieldFromURL(t *testing.T) {
	const promURL = "http://prometheus.monitoring:9090"
	p := NewPrometheusClient(promURL)
	if p == nil {
		t.Fatal("NewPrometheusClient returned nil")
		return
	}
	if p.URL != promURL {
		t.Errorf("URL = %q, want %q", p.URL, promURL)
	}
}

// TestNewPrometheusClient_DefaultHTTPTimeout verifies that the client uses a
// 10-second timeout to prevent slow Prometheus instances from stalling the
// context gathering phase.
func TestNewPrometheusClient_DefaultHTTPTimeout(t *testing.T) {
	p := NewPrometheusClient("http://localhost:9090")
	if p.HTTP == nil {
		t.Fatal("HTTP client must not be nil")
	}
	if p.HTTP.Timeout != 10*time.Second {
		t.Errorf("HTTP.Timeout = %v, want 10s", p.HTTP.Timeout)
	}
}

// TestNewPrometheusClient_HTTPClientIsNotDefault verifies that the client does
// not share http.DefaultClient so its timeout is isolated from other usages.
func TestNewPrometheusClient_HTTPClientIsNotDefault(t *testing.T) {
	p := NewPrometheusClient("http://localhost:9090")
	if p.HTTP == http.DefaultClient {
		t.Error("PrometheusClient must not share http.DefaultClient")
	}
}

// TestNewPrometheusClient_StripsTrailingSlash verifies that a URL configured
// with a trailing slash is normalised so that query paths don't gain a double
// slash (e.g. "http://host:9090//api/v1/query"). This mirrors NewAPIClient's
// opposite normalisation, which always ensures the URL ends with "/".
func TestNewPrometheusClient_StripsTrailingSlash(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"http://prometheus:9090/", "http://prometheus:9090"},
		{"http://prometheus:9090//", "http://prometheus:9090"},
		{"http://prometheus:9090", "http://prometheus:9090"},
		{"http://prometheus:9090/prefix/", "http://prometheus:9090/prefix"},
	}
	for _, tc := range cases {
		p := NewPrometheusClient(tc.input)
		if p.URL != tc.want {
			t.Errorf("NewPrometheusClient(%q).URL = %q, want %q", tc.input, p.URL, tc.want)
		}
	}
}

// TestConfig_BaseConfig verifies that the k8s Config.BaseConfig() method
// correctly projects the shared configuration fields.
func TestK8sConfig_BaseConfig(t *testing.T) {
	cfg := Config{
		ClaudeModel:     "claude-sonnet-4-5",
		CooldownSeconds: 120,
		Port:            "9090",
		WebhookSecret:   "wh-secret",
		APIBaseURL:      "https://openrouter.ai/api/v1/chat/completions",
		APIKey:          "openrouter-key",
	}
	bc := cfg.BaseConfig()
	if bc.ClaudeModel != cfg.ClaudeModel {
		t.Errorf("ClaudeModel = %q, want %q", bc.ClaudeModel, cfg.ClaudeModel)
	}
	if bc.CooldownSeconds != cfg.CooldownSeconds {
		t.Errorf("CooldownSeconds = %d, want %d", bc.CooldownSeconds, cfg.CooldownSeconds)
	}
	if bc.Port != cfg.Port {
		t.Errorf("Port = %q, want %q", bc.Port, cfg.Port)
	}
	if bc.WebhookSecret != cfg.WebhookSecret {
		t.Errorf("WebhookSecret = %q, want %q", bc.WebhookSecret, cfg.WebhookSecret)
	}
	if bc.APIBaseURL != cfg.APIBaseURL {
		t.Errorf("APIBaseURL = %q, want %q", bc.APIBaseURL, cfg.APIBaseURL)
	}
	if bc.APIKey != cfg.APIKey {
		t.Errorf("APIKey = %q, want %q", bc.APIKey, cfg.APIKey)
	}
}

// TestK8sConfig_BaseConfig_ZeroValue verifies that a zero Config produces a
// zero shared.BaseConfig without panicking.
func TestK8sConfig_BaseConfig_ZeroValue(t *testing.T) {
	var cfg Config
	bc := cfg.BaseConfig()
	if bc != (shared.BaseConfig{}) {
		t.Errorf("zero Config.BaseConfig() = %+v, want zero value", bc)
	}
}

// TestConfig_MaxAgentRounds is a compile-time shape check: it fails to build
// if MaxAgentRounds is absent from Config, and fails at runtime if the field
// does not round-trip the assigned value.
func TestConfig_MaxAgentRounds(t *testing.T) {
	cfg := Config{MaxAgentRounds: 7}
	if cfg.MaxAgentRounds != 7 {
		t.Fatalf("expected 7, got %d", cfg.MaxAgentRounds)
	}
}
