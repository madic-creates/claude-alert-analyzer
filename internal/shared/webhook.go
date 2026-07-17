package shared

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// WebhookTokenHash hashes the expected Authorization header value for the
// given webhook secret. Hashing the expected token once at handler
// construction lets the per-request comparison always operate on equal-length
// (32-byte) inputs. subtle.ConstantTimeCompare returns 0 immediately when
// input lengths differ, which would otherwise let a remote caller probe the
// secret length by varying the Authorization header length.
func WebhookTokenHash(secret string) [sha256.Size]byte {
	return sha256.Sum256([]byte("Bearer " + secret))
}

// CheckWebhookAuth compares the request's Authorization header against the
// expected token hash in constant time. On mismatch it writes a 401 response
// and returns (http.StatusUnauthorized, false); the caller records the status
// via its webhook-outcome metric and must return without further processing.
func CheckWebhookAuth(w http.ResponseWriter, r *http.Request, expectedTokenHash [sha256.Size]byte) (int, bool) {
	gotHash := sha256.Sum256([]byte(r.Header.Get("Authorization")))
	if subtle.ConstantTimeCompare(gotHash[:], expectedTokenHash[:]) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return http.StatusUnauthorized, false
	}
	return http.StatusOK, true
}

// DecodeWebhookBody reads the size-limited request body and unmarshals it
// into v. On failure it writes the appropriate error response — 413 when the
// body exceeds maxBytes, 400 on read or JSON errors — and returns
// (status, false); the caller records the status via its webhook-outcome
// metric and must return without further processing.
func DecodeWebhookBody(w http.ResponseWriter, r *http.Request, maxBytes int64, v any) (int, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return http.StatusRequestEntityTooLarge, false
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return http.StatusBadRequest, false
	}
	if err := json.Unmarshal(body, v); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return http.StatusBadRequest, false
	}
	return http.StatusOK, true
}
