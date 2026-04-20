package checkmk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
)

func TestValidateAndDescribeHost_Match(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/objects/host_config/testhost" {
			http.NotFound(w, r)
			return
		}
		resp := checkmkHostResponse{
			ID: "testhost",
			Extensions: checkmkHostExtensions{
				Attributes: checkmkHostAttributes{IPAddress: "192.168.1.1"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	apiClient := &APIClient{HTTP: srv.Client(), URL: srv.URL + "/", User: "automation", Secret: "secret"}
	_, err := apiClient.ValidateAndDescribeHost(context.Background(), "testhost", "192.168.1.1")
	if err != nil {
		t.Errorf("expected valid host, got error: %v", err)
	}
}

func TestValidateAndDescribeHost_AddressMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := checkmkHostResponse{
			ID: "testhost",
			Extensions: checkmkHostExtensions{
				Attributes: checkmkHostAttributes{IPAddress: "192.168.1.1"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	apiClient := &APIClient{HTTP: srv.Client(), URL: srv.URL + "/", User: "automation", Secret: "secret"}
	_, err := apiClient.ValidateAndDescribeHost(context.Background(), "testhost", "10.0.0.99")
	if err == nil {
		t.Error("expected error for address mismatch")
	}
}

func TestValidateAndDescribeHost_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	apiClient := &APIClient{HTTP: srv.Client(), URL: srv.URL + "/", User: "automation", Secret: "secret"}
	_, err := apiClient.ValidateAndDescribeHost(context.Background(), "unknown", "1.2.3.4")
	if err == nil {
		t.Error("expected error for unknown host")
	}
}

func TestValidateAndDescribeHost_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "internal server error")
	}))
	defer srv.Close()

	apiClient := &APIClient{HTTP: srv.Client(), URL: srv.URL + "/", User: "automation", Secret: "secret"}
	_, err := apiClient.ValidateAndDescribeHost(context.Background(), "host1", "1.2.3.4")
	if err == nil {
		t.Error("expected error for 500 response")
	}
	if err != nil && !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention HTTP status 500, got: %v", err)
	}
}

func TestValidateAndDescribeHost_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `not valid json at all`)
	}))
	defer srv.Close()

	apiClient := &APIClient{HTTP: srv.Client(), URL: srv.URL + "/", User: "automation", Secret: "secret"}
	_, err := apiClient.ValidateAndDescribeHost(context.Background(), "host1", "1.2.3.4")
	if err == nil {
		t.Error("expected error for malformed JSON response")
	}
	if err != nil && !strings.Contains(err.Error(), "parse host response") {
		t.Errorf("error should mention parse failure, got: %v", err)
	}
}

func TestValidateAndDescribeHost_ReturnsAIContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"id": "webserver01",
			"extensions": {
				"attributes": {
					"ipaddress": "10.0.0.1",
					"ip_address_family": "ipv4",
					"ai_context": "Debian 12, Nginx. Config: /etc/nginx/sites-enabled/."
				}
			}
		}`)
	}))
	defer srv.Close()

	apiClient := &APIClient{HTTP: srv.Client(), URL: srv.URL + "/", User: "automation", Secret: "secret"}
	hostInfo, err := apiClient.ValidateAndDescribeHost(context.Background(), "webserver01", "10.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hostInfo.AIContext != "Debian 12, Nginx. Config: /etc/nginx/sites-enabled/." {
		t.Errorf("expected ai_context, got %q", hostInfo.AIContext)
	}
}

func TestValidateAndDescribeHost_NoIPAddress(t *testing.T) {
	// When a CheckMK host has no ipaddress attribute configured, ValidateAndDescribeHost
	// must return an error describing the missing configuration rather than silently
	// accepting the host. Without an IP address there is no verified address to use
	// for SSH connectivity or to compare against the webhook's host_address field.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := checkmkHostResponse{
			ID: "noiphost",
			Extensions: checkmkHostExtensions{
				Attributes: checkmkHostAttributes{IPAddress: ""}, // no IP configured
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	apiClient := &APIClient{HTTP: srv.Client(), URL: srv.URL + "/", User: "automation", Secret: "secret"}
	_, err := apiClient.ValidateAndDescribeHost(context.Background(), "noiphost", "10.0.0.1")
	if err == nil {
		t.Fatal("expected error when host has no IP address configured, got nil")
	}
	if !strings.Contains(err.Error(), "no IP address configured") {
		t.Errorf("error should mention 'no IP address configured', got: %v", err)
	}
}

func TestValidateAndDescribeHost_NoAIContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := checkmkHostResponse{
			ID: "plainhost",
			Extensions: checkmkHostExtensions{
				Attributes: checkmkHostAttributes{IPAddress: "10.0.0.2"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	apiClient := &APIClient{HTTP: srv.Client(), URL: srv.URL + "/", User: "automation", Secret: "secret"}
	hostInfo, err := apiClient.ValidateAndDescribeHost(context.Background(), "plainhost", "10.0.0.2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hostInfo.AIContext != "" {
		t.Errorf("expected empty ai_context, got %q", hostInfo.AIContext)
	}
}

func TestGatherContext_WithHostContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"value":[]}`)
	}))
	defer srv.Close()

	apiClient := &APIClient{HTTP: srv.Client(), URL: srv.URL + "/", User: "automation", Secret: "secret"}
	alert := shared.AlertPayload{
		Fields: map[string]string{
			"hostname":            "web01",
			"host_address":        "10.0.0.1",
			"service_description": "CPU",
			"service_state":       "WARN",
			"service_output":      "high",
			"notification_type":   "PROBLEM",
			"perf_data":           "",
		},
	}
	hostInfo := &HostInfo{AIContext: "Debian 12, Nginx reverse proxy"}

	actx := GatherContext(context.Background(), apiClient, alert, hostInfo)

	if len(actx.Sections) < 3 {
		t.Fatalf("expected at least 3 sections, got %d", len(actx.Sections))
	}
	if actx.Sections[0].Name != "Host Context (operator-provided)" {
		t.Errorf("first section should be host context, got %q", actx.Sections[0].Name)
	}
	if actx.Sections[0].Content != "Debian 12, Nginx reverse proxy" {
		t.Errorf("unexpected content: %q", actx.Sections[0].Content)
	}
	if actx.Sections[1].Name != "Alert Details" {
		t.Errorf("second section should be alert details, got %q", actx.Sections[1].Name)
	}
}

func TestGatherContext_NilHostInfo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"value":[]}`)
	}))
	defer srv.Close()

	apiClient := &APIClient{HTTP: srv.Client(), URL: srv.URL + "/", User: "automation", Secret: "secret"}
	alert := shared.AlertPayload{
		Fields: map[string]string{
			"hostname":            "web01",
			"host_address":        "10.0.0.1",
			"service_description": "CPU",
			"service_state":       "WARN",
			"service_output":      "high",
			"notification_type":   "PROBLEM",
			"perf_data":           "",
		},
	}

	actx := GatherContext(context.Background(), apiClient, alert, nil)

	if len(actx.Sections) != 2 {
		t.Fatalf("expected 2 sections, got %d", len(actx.Sections))
	}
	if actx.Sections[0].Name != "Alert Details" {
		t.Errorf("first section should be alert details, got %q", actx.Sections[0].Name)
	}
}

func TestGatherContext_HostContextSanitized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"value":[]}`)
	}))
	defer srv.Close()

	apiClient := &APIClient{HTTP: srv.Client(), URL: srv.URL + "/", User: "automation", Secret: "secret"}
	alert := shared.AlertPayload{
		Fields: map[string]string{
			"hostname":            "web01",
			"host_address":        "10.0.0.1",
			"service_description": "CPU",
			"service_state":       "WARN",
			"service_output":      "high",
			"notification_type":   "PROBLEM",
			"perf_data":           "",
		},
	}

	t.Run("strips control chars", func(t *testing.T) {
		hostInfo := &HostInfo{AIContext: "Debian\x00 12\x07"}
		actx := GatherContext(context.Background(), apiClient, alert, hostInfo)
		if actx.Sections[0].Content != "Debian 12" {
			t.Errorf("expected control chars stripped, got %q", actx.Sections[0].Content)
		}
	})

	t.Run("trims whitespace", func(t *testing.T) {
		hostInfo := &HostInfo{AIContext: "  Debian 12  "}
		actx := GatherContext(context.Background(), apiClient, alert, hostInfo)
		if actx.Sections[0].Content != "Debian 12" {
			t.Errorf("expected trimmed, got %q", actx.Sections[0].Content)
		}
	})

	t.Run("truncates over 2048 bytes", func(t *testing.T) {
		long := strings.Repeat("A", 2100)
		hostInfo := &HostInfo{AIContext: long}
		actx := GatherContext(context.Background(), apiClient, alert, hostInfo)
		content := actx.Sections[0].Content
		if len(content) > 2048 {
			t.Errorf("expected truncation within 2048 bytes, got length %d", len(content))
		}
		if !strings.HasSuffix(content, " [truncated]") {
			t.Errorf("expected truncation marker, got %q", content[len(content)-20:])
		}
	})

	t.Run("truncation preserves valid UTF-8", func(t *testing.T) {
		// Place a 4-byte emoji right at the truncation boundary
		emoji := "🚀" // 4 bytes
		long := strings.Repeat("A", 2046) + emoji + strings.Repeat("B", 100)
		hostInfo := &HostInfo{AIContext: long}
		actx := GatherContext(context.Background(), apiClient, alert, hostInfo)
		content := actx.Sections[0].Content
		if !utf8.ValidString(content) {
			t.Fatal("truncation produced invalid UTF-8")
		}
		if !strings.HasSuffix(content, " [truncated]") {
			t.Errorf("expected truncation marker")
		}
	})

	t.Run("empty after sanitize skips section", func(t *testing.T) {
		hostInfo := &HostInfo{AIContext: "  \x00\x07  "}
		actx := GatherContext(context.Background(), apiClient, alert, hostInfo)
		if actx.Sections[0].Name == "Host Context (operator-provided)" {
			t.Error("expected no host context section for empty-after-sanitize input")
		}
	})

	t.Run("preserves newlines in multi-line context", func(t *testing.T) {
		// Operators commonly write multi-line AI context, e.g.:
		//   "Debian 12, Nginx.\nConfig: /etc/nginx/sites-enabled/."
		// Stripping \n would collapse the text and make it harder for Claude
		// to parse distinct fields, so newlines must survive sanitization.
		multiLine := "Debian 12, Nginx.\nConfig: /etc/nginx/sites-enabled/.\nDeployed via Ansible."
		hostInfo := &HostInfo{AIContext: multiLine}
		actx := GatherContext(context.Background(), apiClient, alert, hostInfo)
		if actx.Sections[0].Name != "Host Context (operator-provided)" {
			t.Fatalf("expected host context section, got %q", actx.Sections[0].Name)
		}
		if actx.Sections[0].Content != multiLine {
			t.Errorf("newlines stripped from multi-line context:\n  got:  %q\n  want: %q",
				actx.Sections[0].Content, multiLine)
		}
	})

	t.Run("strips carriage returns but preserves newlines", func(t *testing.T) {
		// Windows-style CRLF line endings: \r should be stripped, \n kept.
		crlf := "Line one.\r\nLine two.\r\nLine three."
		want := "Line one.\nLine two.\nLine three."
		hostInfo := &HostInfo{AIContext: crlf}
		actx := GatherContext(context.Background(), apiClient, alert, hostInfo)
		if actx.Sections[0].Name != "Host Context (operator-provided)" {
			t.Fatalf("expected host context section, got %q", actx.Sections[0].Name)
		}
		if actx.Sections[0].Content != want {
			t.Errorf("CRLF not normalised correctly:\n  got:  %q\n  want: %q",
				actx.Sections[0].Content, want)
		}
	})

	t.Run("secrets redacted in operator-provided context", func(t *testing.T) {
		// Operators might accidentally include credentials in the ai_context field,
		// e.g. when documenting database connection details. These must be redacted
		// before the context is sent to the Claude API, just like service_output and
		// other alert fields.
		hostInfo := &HostInfo{AIContext: "Debian 12, Nginx. DB connect: password=s3cr3t host=db.internal"}
		actx := GatherContext(context.Background(), apiClient, alert, hostInfo)
		if actx.Sections[0].Name != "Host Context (operator-provided)" {
			t.Fatalf("expected host context section, got %q", actx.Sections[0].Name)
		}
		if strings.Contains(actx.Sections[0].Content, "s3cr3t") {
			t.Errorf("secret not redacted from ai_context: %q", actx.Sections[0].Content)
		}
		if !strings.Contains(actx.Sections[0].Content, "[REDACTED]") {
			t.Errorf("expected [REDACTED] marker in ai_context, got: %q", actx.Sections[0].Content)
		}
	})
}

func TestValidateAndDescribeHost_RejectsInvalidHostname(t *testing.T) {
	apiClient := &APIClient{HTTP: http.DefaultClient, URL: "http://localhost/api/", User: "automation", Secret: "secret"}

	tests := []struct {
		name     string
		hostname string
	}{
		{"path traversal", "../../etc/passwd"},
		{"null byte", "host\x00evil"},
		{"spaces", "host name"},
		{"empty string", ""},
		{"forward slash", "host/evil"},
		{"backslash", "host\\evil"},
		{"url encoded traversal", "..%2F..%2Fetc%2Fpasswd"},
		{"leading dash", "-badhost"},
		{"trailing dash", "badhost-"},
		{"leading dot", ".hidden"},
		{"trailing dot", "hidden."},
		// RFC 1035 limits a fully-qualified domain name to 253 characters.
		// The regex previously used {0,253} in the middle group, which allowed
		// 1 + 253 + 1 = 255 characters — two over the limit.
		{"254 chars (over limit)", strings.Repeat("a", 254)},
		{"255 chars (over limit)", strings.Repeat("a", 255)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := apiClient.ValidateAndDescribeHost(context.Background(), tt.hostname, "1.2.3.4")
			if err == nil {
				t.Errorf("expected error for hostname %q, got nil", tt.hostname)
			}
			if err != nil && !strings.Contains(err.Error(), "invalid hostname") {
				t.Errorf("expected 'invalid hostname' error, got: %v", err)
			}
		})
	}
}

func TestValidateAndDescribeHost_AcceptsValidHostname(t *testing.T) {
	// This test verifies that isValidHostname accepts legitimate hostnames.
	// We use a test server that returns 404 for any host — the point is that
	// the call must NOT fail with "invalid hostname".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	apiClient := &APIClient{HTTP: srv.Client(), URL: srv.URL + "/", User: "automation", Secret: "secret"}

	tests := []struct {
		name     string
		hostname string
	}{
		{"simple hostname", "webserver01"},
		{"FQDN", "web01.example.com"},
		{"IPv4 address", "192.168.1.1"},
		{"hostname with dash", "my-host"},
		{"hostname with underscore", "my_host"},
		{"single char", "a"},
		{"two chars", "ab"},
		{"uppercase", "MYHOST"},
		{"mixed case FQDN", "Web01.Example.COM"},
		// 253-char hostname is exactly at the RFC 1035 FQDN limit and must be accepted.
		{"253 chars (at limit)", strings.Repeat("a", 253)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := apiClient.ValidateAndDescribeHost(context.Background(), tt.hostname, "1.2.3.4")
			if err != nil && strings.Contains(err.Error(), "invalid hostname") {
				t.Errorf("hostname %q should be accepted, got: %v", tt.hostname, err)
			}
		})
	}
}

// ----- GetHostServices tests -----

// TestGetHostServices_WithServices verifies that GetHostServices correctly formats
// service entries returned by the CheckMK API, including state name translation.
func TestGetHostServices_WithServices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"value":[
			{"extensions":{"description":"CPU Usage","state":1,"plugin_output":"CPU at 95%"}},
			{"extensions":{"description":"Disk /","state":2,"plugin_output":"Disk 98% full"}},
			{"extensions":{"description":"Ping","state":0,"plugin_output":"OK - rta=1ms"}},
			{"extensions":{"description":"SMART","state":3,"plugin_output":"UNKNOWN status"}}
		]}`)
	}))
	defer srv.Close()

	apiClient := &APIClient{HTTP: srv.Client(), URL: srv.URL + "/", User: "auto", Secret: "secret"}
	result := apiClient.GetHostServices(context.Background(), "host1")

	for _, want := range []string{"CPU Usage", "WARN", "Disk /", "CRIT", "Ping", "OK", "SMART", "UNKNOWN"} {
		if !strings.Contains(result, want) {
			t.Errorf("expected %q in result, got:\n%s", want, result)
		}
	}
	// Each service should be on its own line.
	lines := strings.Split(strings.TrimRight(result, "\n"), "\n")
	if len(lines) != 4 {
		t.Errorf("expected 4 lines, got %d:\n%s", len(lines), result)
	}
}

// TestGetHostServices_UnknownState verifies that state values outside the known
// map (0–3) are rendered as their numeric value rather than an empty string.
func TestGetHostServices_UnknownState(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"value":[{"extensions":{"description":"SvcX","state":99,"plugin_output":"odd"}}]}`)
	}))
	defer srv.Close()

	apiClient := &APIClient{HTTP: srv.Client(), URL: srv.URL + "/", User: "auto", Secret: "secret"}
	result := apiClient.GetHostServices(context.Background(), "host1")

	if !strings.Contains(result, "99") {
		t.Errorf("expected numeric state fallback '99' in result, got: %s", result)
	}
}

// TestGetHostServices_EmptyList verifies the empty-list sentinel message.
func TestGetHostServices_EmptyList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"value":[]}`)
	}))
	defer srv.Close()

	apiClient := &APIClient{HTTP: srv.Client(), URL: srv.URL + "/", User: "auto", Secret: "secret"}
	result := apiClient.GetHostServices(context.Background(), "host1")

	if result != "(no services found)" {
		t.Errorf("expected '(no services found)', got: %s", result)
	}
}

// TestGetHostServices_NonOKStatus verifies that a non-200 HTTP status is
// surfaced in the returned string.
func TestGetHostServices_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	apiClient := &APIClient{HTTP: srv.Client(), URL: srv.URL + "/", User: "auto", Secret: "secret"}
	result := apiClient.GetHostServices(context.Background(), "host1")

	if !strings.Contains(result, "403") {
		t.Errorf("expected HTTP 403 in result, got: %s", result)
	}
}

// TestGetHostServices_InvalidJSON verifies that a malformed response is reported.
func TestGetHostServices_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `not json at all`)
	}))
	defer srv.Close()

	apiClient := &APIClient{HTTP: srv.Client(), URL: srv.URL + "/", User: "auto", Secret: "secret"}
	result := apiClient.GetHostServices(context.Background(), "host1")

	if !strings.Contains(result, "failed to parse") {
		t.Errorf("expected parse error in result, got: %s", result)
	}
}

// TestGetHostServices_SecretsRedactedInOutput verifies that service plugin_output
// containing secrets is passed through RedactSecrets before being returned.
// CheckMK check plugins sometimes emit credentials (DB connection strings, API keys)
// in their output; this guards against forwarding them to the Claude API.
func TestGetHostServices_SecretsRedactedInOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"value":[
			{"extensions":{"description":"DBCheck","state":2,"plugin_output":"CRITICAL - password=hunter2 connection refused"}},
			{"extensions":{"description":"API","state":1,"plugin_output":"WARNING - token=sk-ant-api03-abc123xyz connection slow"}}
		]}`)
	}))
	defer srv.Close()

	apiClient := &APIClient{HTTP: srv.Client(), URL: srv.URL + "/", User: "auto", Secret: "secret"}
	result := apiClient.GetHostServices(context.Background(), "host1")

	if strings.Contains(result, "hunter2") {
		t.Errorf("password not redacted in plugin output, got:\n%s", result)
	}
	if strings.Contains(result, "sk-ant-api03-abc123xyz") {
		t.Errorf("API token not redacted in plugin output, got:\n%s", result)
	}
	if !strings.Contains(result, "[REDACTED]") {
		t.Errorf("expected [REDACTED] marker in result, got:\n%s", result)
	}
	// Service names and states must be preserved
	if !strings.Contains(result, "DBCheck") || !strings.Contains(result, "CRIT") {
		t.Errorf("service metadata should be preserved, got:\n%s", result)
	}
}

// TestGatherContext_ServiceOutputSecretsRedacted verifies that service_output
// from the webhook payload is passed through RedactSecrets before being
// embedded in the Claude prompt. GetHostServices already redacts plugin_output;
// this ensures GatherContext is consistent for the same kind of data.
func TestGatherContext_ServiceOutputSecretsRedacted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"value":[]}`)
	}))
	defer srv.Close()

	apiClient := &APIClient{HTTP: srv.Client(), URL: srv.URL + "/", User: "auto", Secret: "secret"}
	alert := shared.AlertPayload{
		Fields: map[string]string{
			"hostname":            "db01",
			"host_address":        "10.0.0.5",
			"service_description": "MySQL Connections",
			"service_state":       "CRITICAL",
			"service_output":      "CRITICAL - password=s3cr3t connection refused to db01",
			"notification_type":   "PROBLEM",
			"perf_data":           "token=ghp_abc123xyz connections=0",
		},
	}

	actx := GatherContext(context.Background(), apiClient, alert, nil)

	prompt := actx.FormatForPrompt()
	if strings.Contains(prompt, "s3cr3t") {
		t.Errorf("service_output password not redacted in prompt:\n%s", prompt)
	}
	if strings.Contains(prompt, "ghp_abc123xyz") {
		t.Errorf("perf_data token not redacted in prompt:\n%s", prompt)
	}
	if !strings.Contains(prompt, "[REDACTED]") {
		t.Errorf("expected [REDACTED] marker in prompt:\n%s", prompt)
	}
	// Service name and state must be preserved.
	if !strings.Contains(prompt, "MySQL Connections") || !strings.Contains(prompt, "CRITICAL") {
		t.Errorf("service metadata should be preserved:\n%s", prompt)
	}
}

// TestGatherContext_LongPluginOutputIncluded verifies that long_plugin_output from
// the webhook payload is included in the Alert Details section sent to Claude.
// It must be redacted (like service_output and perf_data) and only appear when non-empty.
func TestGatherContext_LongPluginOutputIncluded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"value":[]}`)
	}))
	defer srv.Close()

	apiClient := &APIClient{HTTP: srv.Client(), URL: srv.URL + "/", User: "auto", Secret: "secret"}

	t.Run("included and redacted when non-empty", func(t *testing.T) {
		alert := shared.AlertPayload{
			Fields: map[string]string{
				"hostname":            "web01",
				"host_address":        "10.0.0.1",
				"service_description": "Disk /",
				"service_state":       "CRITICAL",
				"service_output":      "CRITICAL - / 95% full",
				"notification_type":   "PROBLEM",
				"perf_data":           "",
				"long_plugin_output":  "/: 95% (token=ghp_abc123 total=100G used=95G free=5G)\n/boot: 50% total=1G used=512M free=512M",
			},
		}
		actx := GatherContext(context.Background(), apiClient, alert, nil)
		prompt := actx.FormatForPrompt()

		// long_plugin_output content must appear in prompt
		if !strings.Contains(prompt, "Detailed Output") {
			t.Errorf("expected 'Detailed Output' heading in prompt:\n%s", prompt)
		}
		if !strings.Contains(prompt, "/boot") {
			t.Errorf("expected /boot partition line in prompt:\n%s", prompt)
		}
		// secret must be redacted
		if strings.Contains(prompt, "ghp_abc123") {
			t.Errorf("long_plugin_output token not redacted in prompt:\n%s", prompt)
		}
		if !strings.Contains(prompt, "[REDACTED]") {
			t.Errorf("expected [REDACTED] marker in prompt:\n%s", prompt)
		}
	})

	t.Run("omitted when empty", func(t *testing.T) {
		alert := shared.AlertPayload{
			Fields: map[string]string{
				"hostname":            "web01",
				"host_address":        "10.0.0.1",
				"service_description": "Ping",
				"service_state":       "OK",
				"service_output":      "OK - 1.2ms",
				"notification_type":   "RECOVERY",
				"perf_data":           "",
				"long_plugin_output":  "",
			},
		}
		actx := GatherContext(context.Background(), apiClient, alert, nil)
		prompt := actx.FormatForPrompt()

		if strings.Contains(prompt, "Detailed Output") {
			t.Errorf("'Detailed Output' should be absent when long_plugin_output is empty:\n%s", prompt)
		}
	})

	// TestGatherContext_LongPluginOutputTruncated verifies that a very large
	// long_plugin_output is truncated before being embedded in the Claude prompt.
	// Without truncation a verbose plugin (e.g. one that dumps a full directory
	// listing or a lengthy core dump trace) could exhaust the model's context
	// window or significantly inflate analysis costs. The limit (4 KiB) mirrors
	// the truncation applied to SSH command output in agent.go.
	t.Run("truncated when oversized", func(t *testing.T) {
		// Build an output larger than the 4 KiB truncation threshold.
		oversized := strings.Repeat("A", 5000)
		alert := shared.AlertPayload{
			Fields: map[string]string{
				"hostname":            "web01",
				"host_address":        "10.0.0.1",
				"service_description": "LogCheck",
				"service_state":       "CRITICAL",
				"service_output":      "CRITICAL - log errors found",
				"notification_type":   "PROBLEM",
				"perf_data":           "",
				"long_plugin_output":  oversized,
			},
		}
		actx := GatherContext(context.Background(), apiClient, alert, nil)
		prompt := actx.FormatForPrompt()

		if !strings.Contains(prompt, "Detailed Output") {
			t.Errorf("expected 'Detailed Output' heading even for oversized input:\n%s", prompt[:200])
		}
		if !strings.Contains(prompt, "[truncated]") {
			t.Errorf("expected truncation marker for oversized long_plugin_output:\n%s", prompt[:200])
		}
		// The prompt must not contain the full 5000-byte output.
		if strings.Count(prompt, "A") >= 5000 {
			t.Errorf("prompt contains the full oversized long_plugin_output — truncation did not fire")
		}
	})
}

// TestGatherContext_TimestampIncluded verifies that the CheckMK notification
// timestamp is included in the Alert Details section sent to Claude. The timestamp
// tells Claude when the alert fired, which is useful for correlating with
// deployments or other events that happened around the same time.
func TestGatherContext_TimestampIncluded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"value":[]}`)
	}))
	defer srv.Close()

	apiClient := &APIClient{HTTP: srv.Client(), URL: srv.URL + "/", User: "auto", Secret: "secret"}
	alert := shared.AlertPayload{
		Fields: map[string]string{
			"hostname":            "web01",
			"host_address":        "10.0.0.1",
			"service_description": "CPU",
			"service_state":       "CRITICAL",
			"service_output":      "CPU at 99%",
			"notification_type":   "PROBLEM",
			"perf_data":           "",
			"timestamp":           "2024-01-15T03:00:00Z",
		},
	}

	actx := GatherContext(context.Background(), apiClient, alert, nil)
	prompt := actx.FormatForPrompt()

	if !strings.Contains(prompt, "2024-01-15T03:00:00Z") {
		t.Errorf("expected timestamp in alert details prompt, got:\n%s", prompt)
	}
	if !strings.Contains(prompt, "Timestamp") {
		t.Errorf("expected 'Timestamp' label in alert details prompt, got:\n%s", prompt)
	}
}

// TestGatherContext_HostStateIncluded verifies that the host_state field from the
// CheckMK notification is included in the Alert Details section sent to Claude.
// A host's UP/DOWN/UNREACHABLE state is critical for root-cause analysis: if the
// host itself is DOWN, service alerts are typically a consequence rather than
// the root cause, and Claude needs this context to reason correctly.
func TestGatherContext_HostStateIncluded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"value":[]}`)
	}))
	defer srv.Close()

	apiClient := &APIClient{HTTP: srv.Client(), URL: srv.URL + "/", User: "auto", Secret: "secret"}
	alert := shared.AlertPayload{
		Fields: map[string]string{
			"hostname":            "web01",
			"host_address":        "10.0.0.1",
			"host_state":          "DOWN",
			"service_description": "HTTP",
			"service_state":       "CRITICAL",
			"service_output":      "connection refused",
			"notification_type":   "PROBLEM",
			"perf_data":           "",
			"timestamp":           "2024-01-15T03:00:00Z",
		},
	}

	actx := GatherContext(context.Background(), apiClient, alert, nil)
	prompt := actx.FormatForPrompt()

	if !strings.Contains(prompt, "DOWN") {
		t.Errorf("expected host_state 'DOWN' in alert details prompt, got:\n%s", prompt)
	}
	if !strings.Contains(prompt, "Host State") {
		t.Errorf("expected 'Host State' label in alert details prompt, got:\n%s", prompt)
	}
}

// TestGetHostServices_InvalidHostname verifies that the hostname guard fires
// before any network call is made.
func TestGetHostServices_InvalidHostname(t *testing.T) {
	// Use a client that would never succeed — the guard must fire first.
	apiClient := &APIClient{HTTP: http.DefaultClient, URL: "http://127.0.0.1:1/api/", User: "auto", Secret: "secret"}
	result := apiClient.GetHostServices(context.Background(), "../../etc/passwd")

	if !strings.Contains(result, "invalid hostname") {
		t.Errorf("expected 'invalid hostname' in result, got: %s", result)
	}
}

// TestGetHostServices_TruncatesLargeServiceList verifies that when a host has more
// than 100 monitored services, the output is capped to prevent excessive Claude
// token consumption. Non-OK services must appear before OK services so that the
// most diagnostically relevant entries survive truncation.
func TestGetHostServices_TruncatesLargeServiceList(t *testing.T) {
	// Build a response with 110 services: 10 CRIT, 10 WARN, and 90 OK.
	type svcEntry struct {
		Extensions struct {
			Description string `json:"description"`
			State       int    `json:"state"`
			Output      string `json:"plugin_output"`
		} `json:"extensions"`
	}
	var entries []svcEntry
	for i := 0; i < 10; i++ {
		e := svcEntry{}
		e.Extensions.Description = fmt.Sprintf("CritSvc%02d", i)
		e.Extensions.State = 2 // CRIT
		e.Extensions.Output = "critical failure"
		entries = append(entries, e)
	}
	for i := 0; i < 10; i++ {
		e := svcEntry{}
		e.Extensions.Description = fmt.Sprintf("WarnSvc%02d", i)
		e.Extensions.State = 1 // WARN
		e.Extensions.Output = "elevated load"
		entries = append(entries, e)
	}
	for i := 0; i < 90; i++ {
		e := svcEntry{}
		e.Extensions.Description = fmt.Sprintf("OkSvc%03d", i)
		e.Extensions.State = 0 // OK
		e.Extensions.Output = "all good"
		entries = append(entries, e)
	}

	body, err := json.Marshal(map[string]any{"value": entries})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	apiClient := &APIClient{HTTP: srv.Client(), URL: srv.URL + "/", User: "auto", Secret: "secret"}
	result := apiClient.GetHostServices(context.Background(), "host1")

	lines := strings.Split(strings.TrimRight(result, "\n"), "\n")

	// Total lines must be capped: 100 service lines + 1 truncation marker.
	if len(lines) != 101 {
		t.Errorf("expected 101 lines (100 services + truncation marker), got %d", len(lines))
	}

	// The truncation marker must report the correct remaining count.
	lastLine := lines[len(lines)-1]
	if !strings.Contains(lastLine, "10 more services truncated") {
		t.Errorf("expected truncation marker with count 10, got: %q", lastLine)
	}

	// All 10 CRIT and all 10 WARN services must be present (non-OK first).
	for i := 0; i < 10; i++ {
		if !strings.Contains(result, fmt.Sprintf("CritSvc%02d", i)) {
			t.Errorf("CritSvc%02d should survive truncation", i)
		}
		if !strings.Contains(result, fmt.Sprintf("WarnSvc%02d", i)) {
			t.Errorf("WarnSvc%02d should survive truncation", i)
		}
	}

	// The last OK service (OkSvc089) must NOT be present — it was truncated.
	if strings.Contains(result, "OkSvc089") {
		t.Error("OkSvc089 should have been truncated (OK services fill the tail)")
	}
}

// TestNewAPIClient_URLNormalization verifies that NewAPIClient appends a trailing
// slash when the caller omits it. Without normalization the path concatenation
// in ValidateAndDescribeHost and GetHostServices produces broken URLs such as
// "http://host/apiobjects/host_config/..." instead of
// "http://host/api/objects/host_config/...".
func TestNewAPIClient_URLNormalization(t *testing.T) {
	// A test server that records what path it received.
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		http.NotFound(w, r) // 404 is fine; we only care about the path
	}))
	defer srv.Close()

	tests := []struct {
		inputURL string
		wantPath string
	}{
		{
			inputURL: srv.URL + "/cmk/check_mk/api/1.0", // no trailing slash
			wantPath: "/cmk/check_mk/api/1.0/objects/host_config/myhost",
		},
		{
			inputURL: srv.URL + "/cmk/check_mk/api/1.0/", // already has trailing slash
			wantPath: "/cmk/check_mk/api/1.0/objects/host_config/myhost",
		},
	}

	for _, tt := range tests {
		t.Run(tt.inputURL, func(t *testing.T) {
			gotPath = ""
			cfg := Config{
				CheckMKAPIURL:    tt.inputURL,
				CheckMKAPIUser:   "automation",
				CheckMKAPISecret: "secret",
			}
			client := NewAPIClient(cfg)
			client.HTTP = srv.Client()

			// The call will 404, but the path must be correct.
			_, _ = client.ValidateAndDescribeHost(context.Background(), "myhost", "1.2.3.4")

			if gotPath != tt.wantPath {
				t.Errorf("URL path mismatch:\n  got:  %q\n  want: %q", gotPath, tt.wantPath)
			}
		})
	}
}

// TestGetHostServices_CritNotMisclassifiedByDescription is a regression test for
// a bug where the old two-pass sort used strings.Contains(line, ": OK —") to
// detect OK services. A CRIT service whose *description* contained the literal
// text ": OK —" would be placed in the OK bucket and potentially truncated off the
// output, hiding a critical alert from Claude's analysis.
func TestGetHostServices_CritNotMisclassifiedByDescription(t *testing.T) {
	// Build a response with 101 services: 1 CRIT whose description contains
	// ": OK —", and 100 OK services. With the old code the CRIT service would
	// be sorted into the OK bucket and might be truncated; with the fix it must
	// always appear first.
	type svcEntry struct {
		Extensions struct {
			Description string `json:"description"`
			State       int    `json:"state"`
			Output      string `json:"plugin_output"`
		} `json:"extensions"`
	}
	var entries []svcEntry

	// CRIT service whose description contains the substring ": OK —".
	e := svcEntry{}
	e.Extensions.Description = "Status: OK — result probe"
	e.Extensions.State = 2 // CRIT
	e.Extensions.Output = "connection refused"
	entries = append(entries, e)

	// 100 plain OK services to force truncation.
	for i := 0; i < 100; i++ {
		ok := svcEntry{}
		ok.Extensions.Description = fmt.Sprintf("OkSvc%03d", i)
		ok.Extensions.State = 0
		ok.Extensions.Output = "all good"
		entries = append(entries, ok)
	}

	body, err := json.Marshal(map[string]any{"value": entries})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body) //nolint:errcheck
	}))
	defer srv.Close()

	apiClient := &APIClient{HTTP: srv.Client(), URL: srv.URL + "/", User: "auto", Secret: "secret"}
	result := apiClient.GetHostServices(context.Background(), "host1")

	// The CRIT service must be present even though its description contains ": OK —".
	if !strings.Contains(result, "Status: OK — result probe") {
		t.Errorf("CRIT service with ': OK —' in description was incorrectly truncated; result:\n%s", result)
	}
	if !strings.Contains(result, "CRIT") {
		t.Errorf("CRIT state must appear in result; result:\n%s", result)
	}
}

// TestSanitizeHostContext verifies the contract of sanitizeHostContext directly,
// without the overhead of an HTTP test server. The function is used to clean
// operator-provided multi-line host context before it is included in the Claude
// prompt, so correctness of character filtering and truncation matters for both
// prompt quality and token budget.
func TestSanitizeHostContext(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "only whitespace",
			input: "   \t\n  ",
			want:  "",
		},
		{
			name:  "plain text unchanged",
			input: "hello world",
			want:  "hello world",
		},
		{
			name:  "leading and trailing whitespace trimmed",
			input: "  hello  ",
			want:  "hello",
		},
		{
			name:  "tabs preserved",
			input: "col1\tcol2",
			want:  "col1\tcol2",
		},
		{
			name:  "newlines preserved",
			input: "line1\nline2",
			want:  "line1\nline2",
		},
		{
			name:  "carriage returns stripped (CRLF normalised to LF)",
			input: "line1\r\nline2",
			want:  "line1\nline2",
		},
		{
			name:  "bare CR stripped",
			input: "line1\rline2",
			want:  "line1line2",
		},
		{
			name:  "null bytes stripped",
			input: "abc\x00def",
			want:  "abcdef",
		},
		{
			name:  "bell and other control chars stripped",
			input: "a\x07b\x1bc",
			want:  "abc",
		},
		{
			name:  "only control chars becomes empty",
			input: "\x00\x01\x02\x03",
			want:  "",
		},
		{
			name:  "multi-byte runes preserved",
			input: "héllo wörld",
			want:  "héllo wörld",
		},
		{
			name:  "string exactly at limit not truncated",
			input: strings.Repeat("a", maxAIContextBytes),
			want:  strings.Repeat("a", maxAIContextBytes),
		},
		{
			name:  "string one byte over limit is truncated with marker",
			input: strings.Repeat("a", maxAIContextBytes+1),
			want:  strings.Repeat("a", maxAIContextBytes-len(" [truncated]")) + " [truncated]",
		},
		{
			name: "truncation preserves valid UTF-8 at boundary",
			// Build a string where a multi-byte rune straddles the cut point.
			// 'é' is 2 bytes (U+00E9). Fill to just before the cut point with
			// ASCII 'a', then append 'é' so that the first byte of 'é' lands at
			// the cut position. strings.ToValidUTF8 must drop the incomplete rune.
			input: func() string {
				const marker = " [truncated]"
				cutAt := maxAIContextBytes - len(marker)
				// cutAt-1 'a' bytes + 'é' (2 bytes) pushes one byte past cutAt.
				return strings.Repeat("a", cutAt-1) + "é" + strings.Repeat("a", 20)
			}(),
			want: func() string {
				const marker = " [truncated]"
				cutAt := maxAIContextBytes - len(marker)
				// The incomplete first byte of 'é' at position cutAt is dropped by
				// strings.ToValidUTF8, leaving cutAt-1 'a' bytes before the marker.
				return strings.Repeat("a", cutAt-1) + marker
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeHostContext(tc.input)
			if got != tc.want {
				t.Errorf("sanitizeHostContext(%q)\n got  %q\n want %q", tc.input, got, tc.want)
			}
			// Output must always be valid UTF-8.
			if !utf8.ValidString(got) {
				t.Errorf("sanitizeHostContext returned invalid UTF-8: %q", got)
			}
			// Output must never exceed maxAIContextBytes.
			if len(got) > maxAIContextBytes {
				t.Errorf("output length %d exceeds maxAIContextBytes %d", len(got), maxAIContextBytes)
			}
		})
	}
}
