package shared

import (
	"testing"
)

func TestFormatForPrompt(t *testing.T) {
	ac := AnalysisContext{
		Sections: []ContextSection{
			{Name: "Metrics", Content: "cpu=90%"},
			{Name: "Events", Content: "pod restarted"},
		},
	}
	got := ac.FormatForPrompt()
	want := "## Metrics\ncpu=90%\n\n## Events\npod restarted\n\n"
	if got != want {
		t.Errorf("FormatForPrompt() =\n%q\nwant:\n%q", got, want)
	}
}

func TestFormatForPrompt_Empty(t *testing.T) {
	ac := AnalysisContext{}
	got := ac.FormatForPrompt()
	if got != "" {
		t.Errorf("FormatForPrompt() = %q, want empty", got)
	}
}

func TestAlertPayload_HasSeverityField(t *testing.T) {
	p := AlertPayload{SeverityLevel: SeverityCritical}
	if p.SeverityLevel != SeverityCritical {
		t.Errorf("expected SeverityCritical, got %v", p.SeverityLevel)
	}
}
