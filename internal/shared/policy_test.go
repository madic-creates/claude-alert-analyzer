package shared

import (
	"strings"
	"testing"
)

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

func TestLoadPolicy_DefaultsWhenNoOverrides(t *testing.T) {
	t.Setenv("MAX_AGENT_ROUNDS", "10")

	p, err := LoadPolicy(BaseConfig{ClaudeModel: "claude-sonnet-4-6"})
	if err != nil {
		t.Fatal(err)
	}

	if p.DefaultModel != "claude-sonnet-4-6" {
		t.Errorf("DefaultModel: got %q", p.DefaultModel)
	}
	if p.DefaultMaxRounds != 10 {
		t.Errorf("DefaultMaxRounds: got %d", p.DefaultMaxRounds)
	}
	if len(p.ModelOverrides) != 0 {
		t.Errorf("ModelOverrides: expected empty, got %v", p.ModelOverrides)
	}
	if len(p.RoundsOverrides) != 0 {
		t.Errorf("RoundsOverrides: expected empty, got %v", p.RoundsOverrides)
	}
}

func TestLoadPolicy_AppliesModelOverrides(t *testing.T) {
	t.Setenv("CLAUDE_MODEL_CRITICAL", "claude-opus-4-7")
	t.Setenv("CLAUDE_MODEL_WARNING", "claude-haiku-4-5")
	t.Setenv("CLAUDE_MODEL_INFO", "  ") // whitespace-only must be ignored

	p, err := LoadPolicy(BaseConfig{ClaudeModel: "claude-sonnet-4-6"})
	if err != nil {
		t.Fatal(err)
	}

	if p.ModelFor(SeverityCritical) != "claude-opus-4-7" {
		t.Errorf("critical: got %q", p.ModelFor(SeverityCritical))
	}
	if p.ModelFor(SeverityWarning) != "claude-haiku-4-5" {
		t.Errorf("warning: got %q", p.ModelFor(SeverityWarning))
	}
	if p.ModelFor(SeverityInfo) != "claude-sonnet-4-6" {
		t.Errorf("info (whitespace-only ignored): got %q", p.ModelFor(SeverityInfo))
	}
}

func TestLoadPolicy_AppliesRoundsOverrides_IncludingZero(t *testing.T) {
	t.Setenv("MAX_AGENT_ROUNDS_INFO", "0")
	t.Setenv("MAX_AGENT_ROUNDS_WARNING", "3")

	p, err := LoadPolicy(BaseConfig{ClaudeModel: "x"})
	if err != nil {
		t.Fatal(err)
	}

	if p.MaxRoundsFor(SeverityInfo) != 0 {
		t.Errorf("info: got %d, want 0 (static-only)", p.MaxRoundsFor(SeverityInfo))
	}
	if p.MaxRoundsFor(SeverityWarning) != 3 {
		t.Errorf("warning: got %d, want 3", p.MaxRoundsFor(SeverityWarning))
	}
	if p.MaxRoundsFor(SeverityCritical) != 10 {
		t.Errorf("critical (no override): got %d, want 10", p.MaxRoundsFor(SeverityCritical))
	}
}

func TestLoadPolicy_RejectsOutOfRangeOverride(t *testing.T) {
	t.Setenv("MAX_AGENT_ROUNDS_CRITICAL", "99")

	_, err := LoadPolicy(BaseConfig{ClaudeModel: "x"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "policy:") {
		t.Errorf("error missing 'policy:' prefix: %v", err)
	}
	if !strings.Contains(err.Error(), "MAX_AGENT_ROUNDS_CRITICAL") {
		t.Errorf("error missing offending var name: %v", err)
	}
}

func TestLoadPolicy_RejectsInvalidGlobalRounds(t *testing.T) {
	t.Setenv("MAX_AGENT_ROUNDS", "not-a-number")

	_, err := LoadPolicy(BaseConfig{ClaudeModel: "x"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "MAX_AGENT_ROUNDS") {
		t.Errorf("error missing var name: %v", err)
	}
}
