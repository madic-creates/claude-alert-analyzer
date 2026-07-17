package shared

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestRecoverToolPanicsPassthrough(t *testing.T) {
	wantErr := errors.New("boom")
	h := RecoverToolPanics(func(name string, input json.RawMessage) (string, error) {
		return "result for " + name, wantErr
	}, nil)

	got, err := h("mytool", json.RawMessage(`{}`))
	if got != "result for mytool" || !errors.Is(err, wantErr) {
		t.Fatalf("passthrough = (%q, %v), want (%q, %v)", got, err, "result for mytool", wantErr)
	}
}

func TestRecoverToolPanicsRecovers(t *testing.T) {
	h := RecoverToolPanics(func(name string, input json.RawMessage) (string, error) {
		panic("nil map write\nsecond line")
	}, nil, "alertname", "TestAlert")

	got, err := h("mytool", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("err = %v, want nil (synthetic result, not loop abort)", err)
	}
	if !strings.Contains(got, "Tool mytool panicked") {
		t.Fatalf("result %q does not contain panic marker", got)
	}
	if strings.Contains(got, "\n") {
		t.Fatalf("result %q contains raw newline; panic value must be sanitized", got)
	}
	if !strings.Contains(got, "continue with a different command") {
		t.Fatalf("result %q missing continue advisory", got)
	}
}
