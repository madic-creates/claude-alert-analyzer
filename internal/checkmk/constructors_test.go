package checkmk

import (
	"net/http"
	"testing"
	"time"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
)

// TestNewAPIClient_FieldsFromConfig verifies that NewAPIClient transfers the
// relevant Config fields to the APIClient struct.
func TestNewAPIClient_FieldsFromConfig(t *testing.T) {
	cfg := Config{
		CheckMKAPIURL:    "https://checkmk.example.com/api/",
		CheckMKAPIUser:   "automation",
		CheckMKAPISecret: "test-secret",
	}
	c := NewAPIClient(cfg)
	if c == nil {
		t.Fatal("NewAPIClient returned nil")
		return
	}
	if c.URL != cfg.CheckMKAPIURL {
		t.Errorf("URL = %q, want %q", c.URL, cfg.CheckMKAPIURL)
	}
	if c.User != cfg.CheckMKAPIUser {
		t.Errorf("User = %q, want %q", c.User, cfg.CheckMKAPIUser)
	}
	if c.Secret != cfg.CheckMKAPISecret {
		t.Errorf("Secret = %q, want %q", c.Secret, cfg.CheckMKAPISecret)
	}
}

// TestNewAPIClient_DefaultHTTPTimeout verifies that the client uses a 10-second
// timeout so slow CheckMK responses don't hang the diagnostic pipeline.
func TestNewAPIClient_DefaultHTTPTimeout(t *testing.T) {
	c := NewAPIClient(Config{})
	if c.HTTP == nil {
		t.Fatal("HTTP client must not be nil")
	}
	if c.HTTP.Timeout != 10*time.Second {
		t.Errorf("HTTP.Timeout = %v, want 10s", c.HTTP.Timeout)
	}
}

// TestNewAPIClient_HTTPClientIsNotDefault verifies that the client creates its
// own *http.Client rather than sharing http.DefaultClient so its timeout is
// isolated.
func TestNewAPIClient_HTTPClientIsNotDefault(t *testing.T) {
	c := NewAPIClient(Config{})
	if c.HTTP == http.DefaultClient {
		t.Error("APIClient must not share http.DefaultClient")
	}
}

// TestConfig_BaseConfig verifies that Config.BaseConfig() correctly maps the
// overlapping fields into the returned shared.BaseConfig.
func TestConfig_BaseConfig(t *testing.T) {
	cfg := Config{
		ClaudeModel:     "claude-sonnet-4-5",
		CooldownSeconds: 300,
		Port:            "8080",
		WebhookSecret:   "webhook-secret",
		APIBaseURL:      "https://api.anthropic.com/v1/messages",
		APIKey:          "api-key-123",
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

// TestConfig_BaseConfig_ZeroValue verifies that the zero value Config converts
// to a zero value shared.BaseConfig without panicking.
func TestConfig_BaseConfig_ZeroValue(t *testing.T) {
	var cfg Config
	bc := cfg.BaseConfig()
	// A zero BaseConfig should have all empty fields.
	if bc != (shared.BaseConfig{}) {
		t.Errorf("zero Config.BaseConfig() = %+v, want zero value", bc)
	}
}
