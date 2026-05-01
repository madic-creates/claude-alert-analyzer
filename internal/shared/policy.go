package shared

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// AnalysisPolicy is a thin decision layer that maps alert severity to model
// and tool-loop budget. It holds no mutable fields of its own; Phase 2 will
// add a Storm pointer for IsDegraded().
type AnalysisPolicy struct {
	DefaultModel     string
	ModelOverrides   map[Severity]string
	DefaultMaxRounds int
	RoundsOverrides  map[Severity]int
	GroupCooldownTTL time.Duration // Phase 2; unused in Phase 1, parsed for forward compat
}

// ModelFor returns the configured model for a given severity, falling back
// to DefaultModel when no override is set.
func (p *AnalysisPolicy) ModelFor(sev Severity) string {
	if model, ok := p.ModelOverrides[sev]; ok && model != "" {
		return model
	}
	return p.DefaultModel
}

// MaxRoundsFor returns the configured tool-loop round budget for a given
// severity, falling back to DefaultMaxRounds. A return value of 0 means
// "static-only analysis" (caller uses Analyze, not RunToolLoop).
func (p *AnalysisPolicy) MaxRoundsFor(sev Severity) int {
	if rounds, ok := p.RoundsOverrides[sev]; ok {
		return rounds
	}
	return p.DefaultMaxRounds
}

// LoadPolicy builds an AnalysisPolicy from a BaseConfig and the optional
// severity-specific environment variables defined in the spec. Returns
// an error if any override fails validation.
func LoadPolicy(base BaseConfig) (*AnalysisPolicy, error) {
	defaultRounds, err := ParseIntEnv("MAX_AGENT_ROUNDS", "10", 1, 50)
	if err != nil {
		return nil, err
	}

	modelOverrides := map[Severity]string{}
	for sev, key := range map[Severity]string{
		SeverityCritical: "CLAUDE_MODEL_CRITICAL",
		SeverityWarning:  "CLAUDE_MODEL_WARNING",
		SeverityInfo:     "CLAUDE_MODEL_INFO",
	} {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			modelOverrides[sev] = v
		}
	}

	roundsOverrides := map[Severity]int{}
	for sev, key := range map[Severity]string{
		SeverityCritical: "MAX_AGENT_ROUNDS_CRITICAL",
		SeverityWarning:  "MAX_AGENT_ROUNDS_WARNING",
		SeverityInfo:     "MAX_AGENT_ROUNDS_INFO",
	} {
		if os.Getenv(key) == "" {
			continue
		}
		v, err := ParseIntEnv(key, "", 0, 50)
		if err != nil {
			return nil, fmt.Errorf("policy: %w", err)
		}
		roundsOverrides[sev] = v
	}

	return &AnalysisPolicy{
		DefaultModel:     base.ClaudeModel,
		ModelOverrides:   modelOverrides,
		DefaultMaxRounds: defaultRounds,
		RoundsOverrides:  roundsOverrides,
	}, nil
}
