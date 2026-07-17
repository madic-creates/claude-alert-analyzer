package shared

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"
)

// ToolHandler is the callback signature RunToolLoop dispatches tool calls to.
type ToolHandler func(name string, input json.RawMessage) (string, error)

// RecoverToolPanics wraps handler with panic recovery so a buggy tool handler
// cannot kill the agentic loop. On panic it logs the recovered value, records
// an "exec_error" agent-tool-call metric (metrics may be nil), and returns a
// synthetic tool result so Claude can move on instead of aborting the entire
// alert analysis. logArgs carry product-specific log context (e.g.
// "alertname", <name> or "hostname", <host>).
//
// The elapsed time recorded on panic is measured from wrapper entry: inner
// handlers define their own start for the normal path; this one is only used
// when a panic propagates out before that recording runs.
func RecoverToolPanics(handler ToolHandler, metrics *AlertMetrics, logArgs ...any) ToolHandler {
	return func(name string, input json.RawMessage) (result string, err error) {
		start := time.Now()
		defer func() {
			if r := recover(); r != nil {
				slog.Error("agent tool handler panicked", append([]any{"tool", name, "recover", r}, logArgs...)...)
				if metrics != nil {
					metrics.RecordAgentToolCall(name, "exec_error", time.Since(start))
				}
				result = fmt.Sprintf("Tool %s panicked: %s — continue with a different command", name, SanitizeAlertField(fmt.Sprintf("%v", r)))
				err = nil
			}
		}()
		return handler(name, input)
	}
}
