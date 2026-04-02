package checkmk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidateHost_Match(t *testing.T) {
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
	err := validateHost(context.Background(), cfg, "testhost", "192.168.1.1")
	if err != nil {
		t.Errorf("expected valid host, got error: %v", err)
	}
}

func TestValidateHost_AddressMismatch(t *testing.T) {
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
	err := validateHost(context.Background(), cfg, "testhost", "10.0.0.99")
	if err == nil {
		t.Error("expected error for address mismatch")
	}
}

func TestValidateHost_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := Config{
		CheckMKAPIURL:    srv.URL + "/",
		CheckMKAPIUser:   "automation",
		CheckMKAPISecret: "secret",
	}
	err := validateHost(context.Background(), cfg, "unknown", "1.2.3.4")
	if err == nil {
		t.Error("expected error for unknown host")
	}
}
