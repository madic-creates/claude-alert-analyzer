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
		if len(content) > 2048+len(" [truncated]") {
			t.Errorf("expected truncation, got length %d", len(content))
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
