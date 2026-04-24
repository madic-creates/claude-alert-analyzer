package shared

import (
	"net/http"
	"testing"
	"time"
)

// TestNewClaudeClient verifies that NewClaudeClient initialises all fields from
// the supplied BaseConfig and attaches an HTTP client with the expected timeout.
func TestNewClaudeClient_FieldsFromConfig(t *testing.T) {
	cfg := BaseConfig{
		APIBaseURL:  "https://api.anthropic.com/v1/messages",
		APIKey:      "sk-test-key",
		ClaudeModel: "claude-sonnet-4-5",
	}
	c := NewClaudeClient(cfg)
	if c == nil {
		t.Fatal("NewClaudeClient returned nil")
		return
	}
	if c.BaseURL != cfg.APIBaseURL {
		t.Errorf("BaseURL = %q, want %q", c.BaseURL, cfg.APIBaseURL)
	}
	if c.APIKey != cfg.APIKey {
		t.Errorf("APIKey = %q, want %q", c.APIKey, cfg.APIKey)
	}
	if c.Model != cfg.ClaudeModel {
		t.Errorf("Model = %q, want %q", c.Model, cfg.ClaudeModel)
	}
	if c.HTTP == nil {
		t.Fatal("HTTP client must not be nil")
	}
}

// TestNewClaudeClient_HTTPTimeout verifies that the default HTTP client carries
// a 120-second timeout so that slow API responses don't hang forever.
func TestNewClaudeClient_HTTPTimeout(t *testing.T) {
	c := NewClaudeClient(BaseConfig{})
	if c.HTTP.Timeout != 120*time.Second {
		t.Errorf("HTTP.Timeout = %v, want 120s", c.HTTP.Timeout)
	}
}

// TestNewNtfyPublisher_FieldsFromArgs verifies that NewNtfyPublisher populates
// all fields from the supplied arguments and attaches default retry delays and
// a 10-second HTTP client.
func TestNewNtfyPublisher_FieldsFromArgs(t *testing.T) {
	p := NewNtfyPublisher("https://ntfy.example.com", "alerts", "my-token")
	if p == nil {
		t.Fatal("NewNtfyPublisher returned nil")
		return
	}
	if p.URL != "https://ntfy.example.com" {
		t.Errorf("URL = %q, want %q", p.URL, "https://ntfy.example.com")
	}
	if p.Topic != "alerts" {
		t.Errorf("Topic = %q, want %q", p.Topic, "alerts")
	}
	if p.Token != "my-token" {
		t.Errorf("Token = %q, want %q", p.Token, "my-token")
	}
}

// TestNewNtfyPublisher_DefaultHTTPClient verifies that the publisher uses an
// HTTP client with a 10-second timeout by default.
func TestNewNtfyPublisher_DefaultHTTPClient(t *testing.T) {
	p := NewNtfyPublisher("http://localhost", "t", "")
	if p.HTTP == nil {
		t.Fatal("HTTP client must not be nil")
	}
	if p.HTTP.Timeout != 10*time.Second {
		t.Errorf("HTTP.Timeout = %v, want 10s", p.HTTP.Timeout)
	}
}

// TestNewNtfyPublisher_DefaultRetryDelays verifies that the publisher receives
// the package-level DefaultNtfyRetryDelays so callers don't need to configure
// retry behaviour themselves.
func TestNewNtfyPublisher_DefaultRetryDelays(t *testing.T) {
	p := NewNtfyPublisher("http://localhost", "t", "")
	if len(p.RetryDelays) != len(DefaultNtfyRetryDelays) {
		t.Errorf("RetryDelays len = %d, want %d", len(p.RetryDelays), len(DefaultNtfyRetryDelays))
	}
	for i, d := range p.RetryDelays {
		if d != DefaultNtfyRetryDelays[i] {
			t.Errorf("RetryDelays[%d] = %v, want %v", i, d, DefaultNtfyRetryDelays[i])
		}
	}
}

// TestNewNtfyPublisher_HTTPClientIsNotDefault verifies that the publisher creates
// its own client rather than using http.DefaultClient, so its timeout is isolated.
func TestNewNtfyPublisher_HTTPClientIsNotDefault(t *testing.T) {
	p := NewNtfyPublisher("http://localhost", "t", "")
	if p.HTTP == http.DefaultClient {
		t.Error("publisher must not share http.DefaultClient — it has its own timeout")
	}
}

// TestNewNtfyPublisher_NormalizesTrailingSlash verifies that NewNtfyPublisher
// strips a trailing slash from the URL so that Publish constructs a valid
// topic URL without a double slash (ntfy.example.com/topic rather than
// ntfy.example.com//topic). Consistent with NewPrometheusClient which applies
// the same normalisation via strings.TrimRight(url, "/").
func TestNewNtfyPublisher_NormalizesTrailingSlash(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"https://ntfy.example.com/", "https://ntfy.example.com"},
		{"https://ntfy.example.com///", "https://ntfy.example.com"},
		{"https://ntfy.example.com", "https://ntfy.example.com"},
	}
	for _, tc := range cases {
		p := NewNtfyPublisher(tc.input, "alerts", "tok")
		if p.URL != tc.want {
			t.Errorf("NewNtfyPublisher(%q).URL = %q, want %q", tc.input, p.URL, tc.want)
		}
	}
}
