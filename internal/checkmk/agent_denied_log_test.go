package checkmk

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
)

// TestDeniedCommandLog verifies that a denied execute_command call logs a
// structured slog.Warn record that includes both "command" and "deny_reason"
// as top-level fields. Previously only "command" was logged; "deny_reason"
// was only returned to Claude as tool-result text, making security-relevant
// denials impossible to query in log aggregators.
func TestDeniedCommandLog(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	old := slog.Default()
	slog.SetDefault(slog.New(handler))
	t.Cleanup(func() { slog.SetDefault(old) })

	runner := &capturingToolRunner{
		calls:  []agentToolCall{{name: "execute_command", input: `{"command": ["rm", "-rf", "/"]}`}},
		result: "analysis",
	}

	_, err := RunAgenticDiagnostics(
		context.Background(),
		Config{SSHDeniedCommands: DefaultDeniedCommands},
		runner, nilDialer{}, nil,
		shared.SeverityWarning, "host1", "10.0.0.1", "ctx", 3, "test-model",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Parse JSON log lines to find the "denied command" record.
	found := false
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if rec["msg"] != "denied command" {
			continue
		}
		found = true
		if _, ok := rec["deny_reason"]; !ok {
			t.Errorf("slog record missing deny_reason field; record: %s", line)
		}
		if _, ok := rec["command"]; !ok {
			t.Errorf("slog record missing command field; record: %s", line)
		}
		if _, ok := rec["hostname"]; !ok {
			t.Errorf("slog record missing hostname field; record: %s", line)
		}
	}
	if !found {
		t.Errorf("no slog warn record with msg=denied command found; log output:\n%s", buf.String())
	}
}
