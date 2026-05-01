package shared

import "testing"

func TestAnalysisPolicy_ModelFor(t *testing.T) {
	t.Run("falls_back_to_default_when_no_overrides", func(t *testing.T) {
		p := &AnalysisPolicy{DefaultModel: "claude-sonnet-4-6"}
		for _, sev := range []Severity{SeverityCritical, SeverityWarning, SeverityInfo, SeverityUnknown} {
			if got := p.ModelFor(sev); got != "claude-sonnet-4-6" {
				t.Errorf("severity %v: got %q, want default", sev, got)
			}
		}
	})

	t.Run("uses_override_when_present", func(t *testing.T) {
		p := &AnalysisPolicy{
			DefaultModel: "claude-sonnet-4-6",
			ModelOverrides: map[Severity]string{
				SeverityCritical: "claude-opus-4-7",
				SeverityWarning:  "claude-haiku-4-5",
			},
		}
		if got := p.ModelFor(SeverityCritical); got != "claude-opus-4-7" {
			t.Errorf("critical: got %q, want claude-opus-4-7", got)
		}
		if got := p.ModelFor(SeverityWarning); got != "claude-haiku-4-5" {
			t.Errorf("warning: got %q, want claude-haiku-4-5", got)
		}
		if got := p.ModelFor(SeverityInfo); got != "claude-sonnet-4-6" {
			t.Errorf("info (no override): got %q, want default", got)
		}
	})
}

func TestAnalysisPolicy_MaxRoundsFor(t *testing.T) {
	t.Run("falls_back_to_default", func(t *testing.T) {
		p := &AnalysisPolicy{DefaultMaxRounds: 10}
		if got := p.MaxRoundsFor(SeverityCritical); got != 10 {
			t.Errorf("got %d, want 10", got)
		}
	})

	t.Run("override_zero_means_static_only", func(t *testing.T) {
		p := &AnalysisPolicy{
			DefaultMaxRounds: 10,
			RoundsOverrides:  map[Severity]int{SeverityInfo: 0},
		}
		if got := p.MaxRoundsFor(SeverityInfo); got != 0 {
			t.Errorf("info override 0: got %d, want 0", got)
		}
		if got := p.MaxRoundsFor(SeverityCritical); got != 10 {
			t.Errorf("critical (no override): got %d, want default 10", got)
		}
	})
}
