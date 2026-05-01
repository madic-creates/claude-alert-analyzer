package k8s

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseKubectlInput_BasicValidation(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name:    "empty argv",
			input:   `{"command":[]}`,
			wantErr: "empty command",
		},
		{
			name:    "argv too long",
			input:   `{"command":[` + strings.Repeat(`"x",`, 64) + `"x"]}`,
			wantErr: "maximum is 64",
		},
		{
			name:    "single arg too long",
			input:   `{"command":["` + strings.Repeat("x", 4097) + `"]}`,
			wantErr: "maximum length",
		},
		{
			name:    "total bytes too long",
			input:   `{"command":[` + strings.Repeat(`"`+strings.Repeat("x", 4096)+`",`, 4) + `"x"]}`,
			wantErr: "exceeds maximum",
		},
		{
			name:    "empty arg",
			input:   `{"command":["get",""]}`,
			wantErr: "is empty",
		},
		{
			name:    "whitespace-only arg",
			input:   `{"command":["get","   "]}`,
			wantErr: "whitespace-only",
		},
		{
			name:    "leading whitespace",
			input:   `{"command":["get"," pods"]}`,
			wantErr: "leading or trailing whitespace",
		},
		{
			name:    "trailing whitespace",
			input:   `{"command":["get","pods "]}`,
			wantErr: "leading or trailing whitespace",
		},
		{
			name:    "newline in arg",
			input:   `{"command":["get","pods\nfoo"]}`,
			wantErr: "control character",
		},
		{
			name:    "tab in arg",
			input:   `{"command":["get","pods\tfoo"]}`,
			wantErr: "control character",
		},
		{
			// U+0080 is a C1 control character. It is a valid Unicode code point
			// that JSON decodes transparently. The Go \u0080 escape is resolved to
			// rune U+0080 at compile time; json.Marshal encodes it as "\u0080" in
			// the JSON output, which json.Unmarshal decodes back to the same rune.
			name:    "C1 control char (U+0080)",
			input:   string(mustMarshalCommand([]string{"get", "pods\u0080"})),
			wantErr: "control character",
		},
		{
			name:    "DEL (0x7f)",
			input:   string(mustMarshalCommand([]string{"get", "pods\x7f"})),
			wantErr: "control character",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseKubectlInput(json.RawMessage(tc.input))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("expected error containing %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}

func TestParseKubectlInput_ValidArgv(t *testing.T) {
	got, err := parseKubectlInput(json.RawMessage(`{"command":["get","pods","-n","monitoring"]}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"get", "pods", "-n", "monitoring"}
	if len(got) != len(want) {
		t.Fatalf("len mismatch: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("argv[%d]: got %q, want %q", i, got[i], want[i])
		}
	}
}

// mustMarshalCommand serializes a kubectl command array to JSON for test
// inputs that require literal control characters that cannot be expressed as
// JSON string escapes in a Go raw-string literal.
func mustMarshalCommand(argv []string) []byte {
	b, err := json.Marshal(struct {
		Command []string `json:"command"`
	}{Command: argv})
	if err != nil {
		panic(err)
	}
	return b
}
