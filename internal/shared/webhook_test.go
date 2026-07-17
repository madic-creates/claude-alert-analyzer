package shared

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckWebhookAuth(t *testing.T) {
	expected := WebhookTokenHash("s3cret")

	tests := []struct {
		name       string
		authHeader string
		wantOK     bool
		wantStatus int
	}{
		{"valid token", "Bearer s3cret", true, http.StatusOK},
		{"wrong token", "Bearer nope", false, http.StatusUnauthorized},
		{"missing header", "", false, http.StatusUnauthorized},
		{"token without scheme", "s3cret", false, http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/webhook", nil)
			if tt.authHeader != "" {
				r.Header.Set("Authorization", tt.authHeader)
			}
			w := httptest.NewRecorder()
			status, ok := CheckWebhookAuth(w, r, expected)
			if ok != tt.wantOK || status != tt.wantStatus {
				t.Fatalf("CheckWebhookAuth() = (%d, %v), want (%d, %v)", status, ok, tt.wantStatus, tt.wantOK)
			}
			if !tt.wantOK && w.Code != http.StatusUnauthorized {
				t.Fatalf("response code = %d, want 401", w.Code)
			}
		})
	}
}

func TestDecodeWebhookBody(t *testing.T) {
	type payload struct {
		Name string `json:"name"`
	}

	t.Run("valid JSON", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(`{"name":"x"}`))
		w := httptest.NewRecorder()
		var v payload
		status, ok := DecodeWebhookBody(w, r, 1024, &v)
		if !ok || status != http.StatusOK {
			t.Fatalf("DecodeWebhookBody() = (%d, %v), want (200, true)", status, ok)
		}
		if v.Name != "x" {
			t.Fatalf("decoded Name = %q, want %q", v.Name, "x")
		}
	})

	t.Run("body too large", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(make([]byte, 2048)))
		w := httptest.NewRecorder()
		var v payload
		status, ok := DecodeWebhookBody(w, r, 1024, &v)
		if ok || status != http.StatusRequestEntityTooLarge {
			t.Fatalf("DecodeWebhookBody() = (%d, %v), want (413, false)", status, ok)
		}
		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("response code = %d, want 413", w.Code)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(`{not json`))
		w := httptest.NewRecorder()
		var v payload
		status, ok := DecodeWebhookBody(w, r, 1024, &v)
		if ok || status != http.StatusBadRequest {
			t.Fatalf("DecodeWebhookBody() = (%d, %v), want (400, false)", status, ok)
		}
		if w.Code != http.StatusBadRequest {
			t.Fatalf("response code = %d, want 400", w.Code)
		}
	})
}
