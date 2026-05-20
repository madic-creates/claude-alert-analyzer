package shared

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// AnalysisPolicy is a thin decision layer that maps alert severity to model
// and tool-loop budget. Storm is an optional pointer to a StormDetector;
// nil ↔ storm-mode disabled.
type AnalysisPolicy struct {
	DefaultModel     string
	ModelOverrides   map[Severity]string
	DefaultMaxRounds int
	RoundsOverrides  map[Severity]int
	GroupCooldownTTL time.Duration  // 0 ↔ group-cooldown disabled
	Storm            *StormDetector // nil ↔ storm-mode disabled
}

// ModelFor returns the configured model for a given severity, falling back
// to DefaultModel when no override is set.
func (p *AnalysisPolicy) ModelFor(sev Severity) string {
	if model, ok := p.ModelOverrides[sev]; ok && model != "" {
		return model
	}
	return p.DefaultModel
}

// AllModels returns the deduplicated set of every model the policy may emit.
// Used at startup to pre-materialize alert_analyzer_claude_tokens_total series
// so dashboard queries return 0 instead of "no data" before the first Claude
// call.
func (p *AnalysisPolicy) AllModels() []string {
	seen := map[string]struct{}{}
	out := []string{}
	add := func(m string) {
		if m == "" {
			return
		}
		if _, ok := seen[m]; ok {
			return
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	add(p.DefaultModel)
	for _, m := range p.ModelOverrides {
		add(m)
	}
	return out
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

// IsDegraded reports whether the analyzer is currently in storm-mode.
// Returns false when Storm is nil (storm-mode disabled).
func (p *AnalysisPolicy) IsDegraded() bool {
	if p == nil || p.Storm == nil {
		return false
	}
	return p.Storm.Count() > p.Storm.Threshold()
}

// LoadPolicy builds an AnalysisPolicy from a BaseConfig and the optional
// Phase 1 + Phase 2 environment variables. Phase 2 vars (all optional):
//   - GROUP_COOLDOWN_SECONDS         (default 0 = disabled)
//   - STORM_MODE_THRESHOLD           (default 0 = disabled)
//
// Returns an error if any value fails range validation.
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
		SeverityUnknown:  "CLAUDE_MODEL_UNKNOWN",
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
		SeverityUnknown:  "MAX_AGENT_ROUNDS_UNKNOWN",
	} {
		// Treat whitespace-only the same as unset, matching the CLAUDE_MODEL_*
		// loop above. Operators sometimes leave a ConfigMap value as "  " when
		// disabling an override; the model loop silently ignores that, so the
		// rounds loop must do the same instead of failing startup with a
		// confusing strconv.Atoi error.
		if strings.TrimSpace(os.Getenv(key)) == "" {
			continue
		}
		v, err := ParseIntEnv(key, "", 0, 50)
		if err != nil {
			return nil, fmt.Errorf("policy: %w", err)
		}
		roundsOverrides[sev] = v
	}

	// Phase 2: group cooldown
	groupSecs, err := ParseIntEnv("GROUP_COOLDOWN_SECONDS", "0", 0, 86400)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}

	// Phase 2: storm mode
	stormThreshold, err := ParseIntEnv("STORM_MODE_THRESHOLD", "0", 0, 100000)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	// NewStormDetector returns nil when threshold <= 0 — that is the
	// disabled-default and the Storm field stays nil so IsDegraded() → false.
	storm := NewStormDetector(stormThreshold, time.Now)

	return &AnalysisPolicy{
		DefaultModel:     base.ClaudeModel,
		ModelOverrides:   modelOverrides,
		DefaultMaxRounds: defaultRounds,
		RoundsOverrides:  roundsOverrides,
		GroupCooldownTTL: time.Duration(groupSecs) * time.Second,
		Storm:            storm,
	}, nil
}
