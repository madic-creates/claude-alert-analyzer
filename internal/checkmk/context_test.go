package checkmk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

	cfg := Config{
		CheckMKAPIURL:    srv.URL + "/",
		CheckMKAPIUser:   "automation",
		CheckMKAPISecret: "secret",
	}
	_, err := ValidateAndDescribeHost(context.Background(), cfg, "testhost", "192.168.1.1")
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

	cfg := Config{
		CheckMKAPIURL:    srv.URL + "/",
		CheckMKAPIUser:   "automation",
		CheckMKAPISecret: "secret",
	}
	_, err := ValidateAndDescribeHost(context.Background(), cfg, "testhost", "10.0.0.99")
	if err == nil {
		t.Error("expected error for address mismatch")
	}
}

func TestValidateAndDescribeHost_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := Config{
		CheckMKAPIURL:    srv.URL + "/",
		CheckMKAPIUser:   "automation",
		CheckMKAPISecret: "secret",
	}
	_, err := ValidateAndDescribeHost(context.Background(), cfg, "unknown", "1.2.3.4")
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

	cfg := Config{
		CheckMKAPIURL:    srv.URL + "/",
		CheckMKAPIUser:   "automation",
		CheckMKAPISecret: "secret",
	}
	hostInfo, err := ValidateAndDescribeHost(context.Background(), cfg, "webserver01", "10.0.0.1")
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

	cfg := Config{
		CheckMKAPIURL:    srv.URL + "/",
		CheckMKAPIUser:   "automation",
		CheckMKAPISecret: "secret",
	}
	hostInfo, err := ValidateAndDescribeHost(context.Background(), cfg, "plainhost", "10.0.0.2")
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

	cfg := Config{
		CheckMKAPIURL:    srv.URL + "/",
		CheckMKAPIUser:   "automation",
		CheckMKAPISecret: "secret",
	}
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

	actx := GatherContext(context.Background(), cfg, alert, hostInfo)

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

	cfg := Config{
		CheckMKAPIURL:    srv.URL + "/",
		CheckMKAPIUser:   "automation",
		CheckMKAPISecret: "secret",
	}
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

	actx := GatherContext(context.Background(), cfg, alert, nil)

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

	cfg := Config{
		CheckMKAPIURL:    srv.URL + "/",
		CheckMKAPIUser:   "automation",
		CheckMKAPISecret: "secret",
	}
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
		actx := GatherContext(context.Background(), cfg, alert, hostInfo)
		if actx.Sections[0].Content != "Debian 12" {
			t.Errorf("expected control chars stripped, got %q", actx.Sections[0].Content)
		}
	})

	t.Run("trims whitespace", func(t *testing.T) {
		hostInfo := &HostInfo{AIContext: "  Debian 12  "}
		actx := GatherContext(context.Background(), cfg, alert, hostInfo)
		if actx.Sections[0].Content != "Debian 12" {
			t.Errorf("expected trimmed, got %q", actx.Sections[0].Content)
		}
	})

	t.Run("truncates over 2048 bytes", func(t *testing.T) {
		long := strings.Repeat("A", 2100)
		hostInfo := &HostInfo{AIContext: long}
		actx := GatherContext(context.Background(), cfg, alert, hostInfo)
		content := actx.Sections[0].Content
		if len(content) > 2048+len(" [truncated]") {
			t.Errorf("expected truncation, got length %d", len(content))
		}
		if !strings.HasSuffix(content, " [truncated]") {
			t.Errorf("expected truncation marker, got %q", content[len(content)-20:])
		}
	})

	t.Run("empty after sanitize skips section", func(t *testing.T) {
		hostInfo := &HostInfo{AIContext: "  \x00\x07  "}
		actx := GatherContext(context.Background(), cfg, alert, hostInfo)
		if actx.Sections[0].Name == "Host Context (operator-provided)" {
			t.Error("expected no host context section for empty-after-sanitize input")
		}
	})
}
