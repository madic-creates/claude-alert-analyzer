package shared

import (
	"context"
	"encoding/json"
)

// Analyzer performs single-turn Claude analysis.
type Analyzer interface {
	Analyze(ctx context.Context, systemPrompt, userPrompt string) (string, error)
}

// ToolLoopRunner performs multi-turn Claude tool-use conversations.
type ToolLoopRunner interface {
	RunToolLoop(ctx context.Context, systemPrompt, userPrompt string,
		tools []Tool, maxRounds int,
		handleTool func(name string, input json.RawMessage) (string, error),
	) (analysis string, rounds int, exhausted bool, err error)
}
