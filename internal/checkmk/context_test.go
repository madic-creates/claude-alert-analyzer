package checkmk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
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
