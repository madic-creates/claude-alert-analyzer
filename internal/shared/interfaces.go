package shared

import (
	"context"
	"encoding/json"

	"github.com/anthropics/anthropic-sdk-go"
)

// Analyzer performs single-turn Claude analysis.
type Analyzer interface {
	Analyze(ctx context.Context, model, systemPrompt, userPrompt string) (string, error)
}

// ToolLoopRunner performs multi-turn Claude tool-use conversations.
type ToolLoopRunner interface {
	RunToolLoop(
		ctx context.Context,
		model, systemPrompt, userPrompt string,
		tools []anthropic.ToolUnionParam,
		maxRounds int,
		handleTool func(name string, input json.RawMessage) (string, error),
	) (analysis string, rounds int, exhausted bool, err error)
}
