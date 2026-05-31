package checkmk

import (
	"strings"
	"testing"
)

func TestSystemPromptsRequestSummaryLine(t *testing.T) {
	for name, p := range map[string]string{
		"static": StaticAnalysisSystemPrompt,
		"agent":  agentSystemPromptForRounds(10),
	} {
		if !strings.Contains(p, "SUMMARY:") {
			t.Errorf("%s prompt missing SUMMARY: instruction", name)
		}
	}
}
