package shared

import (
	"strings"
	"testing"
	"time"
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

// TestLoadPolicy_AppliesUnknownModelOverride verifies that CLAUDE_MODEL_UNKNOWN
// is read and applied to SeverityUnknown. This completes the per-severity model
// override surface — without this test a regression that drops the UNKNOWN key
// from the override map would go undetected, forcing CheckMK UNKNOWN service
// alerts to always use the default model even when the operator configures an
// override.
func TestLoadPolicy_AppliesUnknownModelOverride(t *testing.T) {
	t.Setenv("CLAUDE_MODEL_UNKNOWN", "claude-haiku-4-5")

	p, err := LoadPolicy(BaseConfig{ClaudeModel: "claude-sonnet-4-6"})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.ModelFor(SeverityUnknown); got != "claude-haiku-4-5" {
		t.Errorf("unknown: got %q, want claude-haiku-4-5", got)
	}
	// Other severities must still fall back to the default.
	if got := p.ModelFor(SeverityWarning); got != "claude-sonnet-4-6" {
		t.Errorf("warning (no override): got %q, want default", got)
	}
}

// TestLoadPolicy_AppliesUnknownRoundsOverride verifies that
// MAX_AGENT_ROUNDS_UNKNOWN is read and applied to SeverityUnknown. Without
// this, operators cannot route CheckMK UNKNOWN service alerts to static-only
// analysis independently of WARNING alerts.
func TestLoadPolicy_AppliesUnknownRoundsOverride(t *testing.T) {
	t.Setenv("MAX_AGENT_ROUNDS_UNKNOWN", "2")

	p, err := LoadPolicy(BaseConfig{ClaudeModel: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.MaxRoundsFor(SeverityUnknown); got != 2 {
		t.Errorf("unknown: got %d, want 2", got)
	}
	if got := p.MaxRoundsFor(SeverityWarning); got != 10 {
		t.Errorf("warning (no override): got %d, want default 10", got)
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

func TestAnalysisPolicy_IsDegradedNilStorm(t *testing.T) {
	p := &AnalysisPolicy{}
	if p.IsDegraded() {
		t.Fatal("nil Storm: IsDegraded should be false")
	}
}

func TestAnalysisPolicy_IsDegradedBelowThreshold(t *testing.T) {
	storm := NewStormDetector(50, time.Now)
	p := &AnalysisPolicy{Storm: storm}
	for i := 0; i < 25; i++ {
		storm.Record()
	}
	if p.IsDegraded() {
		t.Fatalf("count=25 < threshold=50: IsDegraded should be false")
	}
}

func TestAnalysisPolicy_IsDegradedAboveThreshold(t *testing.T) {
	storm := NewStormDetector(10, time.Now)
	p := &AnalysisPolicy{Storm: storm}
	for i := 0; i < 11; i++ {
		storm.Record()
	}
	if !p.IsDegraded() {
		t.Fatal("count=11 > threshold=10: IsDegraded should be true")
	}
}

// TestAnalysisPolicy_IsDegradedAtThreshold verifies that IsDegraded returns
// false when the alert count equals the threshold exactly. IsDegraded uses
// strict greater-than (count > threshold), so count == threshold is not
// degraded — the alert rate must strictly exceed the threshold to engage
// storm-mode. This pin test guards against a future refactor accidentally
// changing > to >=, which would cause count-at-threshold to falsely suppress
// agentic analysis.
func TestAnalysisPolicy_IsDegradedAtThreshold(t *testing.T) {
	storm := NewStormDetector(10, time.Now)
	p := &AnalysisPolicy{Storm: storm}
	for i := 0; i < 10; i++ {
		storm.Record()
	}
	if p.IsDegraded() {
		t.Fatal("count=10 == threshold=10: IsDegraded should be false (uses >, not >=)")
	}
}

// TestLoadPolicy_GroupCooldownSeconds verifies that GROUP_COOLDOWN_SECONDS is
// correctly parsed and mapped to GroupCooldownTTL in seconds. Without this test,
// a mutation of the unit conversion (e.g. * time.Minute instead of * time.Second)
// would go undetected, causing all group-cooldown windows to be 60x longer than
// configured by the operator.
func TestLoadPolicy_GroupCooldownSeconds(t *testing.T) {
	t.Setenv("GROUP_COOLDOWN_SECONDS", "300")

	p, err := LoadPolicy(BaseConfig{ClaudeModel: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if p.GroupCooldownTTL != 300*time.Second {
		t.Errorf("GroupCooldownTTL = %v, want 300s", p.GroupCooldownTTL)
	}
}

// TestLoadPolicy_GroupCooldownDisabledWhenZero verifies that the default value
// GROUP_COOLDOWN_SECONDS=0 leaves GroupCooldownTTL at zero (feature disabled).
func TestLoadPolicy_GroupCooldownDisabledWhenZero(t *testing.T) {
	p, err := LoadPolicy(BaseConfig{ClaudeModel: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if p.GroupCooldownTTL != 0 {
		t.Errorf("GroupCooldownTTL = %v, want 0 (disabled by default)", p.GroupCooldownTTL)
	}
}

// TestLoadPolicy_RejectsInvalidGroupCooldown verifies that an out-of-range
// GROUP_COOLDOWN_SECONDS value causes LoadPolicy to return an error that
// identifies the offending variable.
func TestLoadPolicy_RejectsInvalidGroupCooldown(t *testing.T) {
	t.Setenv("GROUP_COOLDOWN_SECONDS", "86401") // exceeds max of 86400

	_, err := LoadPolicy(BaseConfig{ClaudeModel: "x"})
	if err == nil {
		t.Fatal("expected error for out-of-range GROUP_COOLDOWN_SECONDS, got nil")
	}
	if !strings.Contains(err.Error(), "GROUP_COOLDOWN_SECONDS") {
		t.Errorf("error should mention GROUP_COOLDOWN_SECONDS, got: %v", err)
	}
}

// TestLoadPolicy_StormModeThreshold verifies that STORM_MODE_THRESHOLD=50
// creates a non-nil Storm field with the correct threshold. Without this test,
// a bug that parses the env var but never passes it to NewStormDetector would
// silently disable storm protection even when it is explicitly configured.
func TestLoadPolicy_StormModeThreshold(t *testing.T) {
	t.Setenv("STORM_MODE_THRESHOLD", "50")

	p, err := LoadPolicy(BaseConfig{ClaudeModel: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Storm == nil {
		t.Fatal("Storm should be non-nil when STORM_MODE_THRESHOLD=50")
	}
	if p.Storm.Threshold() != 50 {
		t.Errorf("Storm.Threshold() = %d, want 50", p.Storm.Threshold())
	}
}

// TestLoadPolicy_StormModeDisabledWhenZero verifies that the default value
// STORM_MODE_THRESHOLD=0 leaves Storm as nil (storm-mode disabled).
func TestLoadPolicy_StormModeDisabledWhenZero(t *testing.T) {
	p, err := LoadPolicy(BaseConfig{ClaudeModel: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Storm != nil {
		t.Errorf("Storm should be nil when STORM_MODE_THRESHOLD=0 (default), got %v", p.Storm)
	}
}

// TestLoadPolicy_RejectsInvalidStormThreshold verifies that an out-of-range
// STORM_MODE_THRESHOLD value causes LoadPolicy to return an error that
// identifies the offending variable.
func TestLoadPolicy_RejectsInvalidStormThreshold(t *testing.T) {
	t.Setenv("STORM_MODE_THRESHOLD", "100001") // exceeds max of 100000

	_, err := LoadPolicy(BaseConfig{ClaudeModel: "x"})
	if err == nil {
		t.Fatal("expected error for out-of-range STORM_MODE_THRESHOLD, got nil")
	}
	if !strings.Contains(err.Error(), "STORM_MODE_THRESHOLD") {
		t.Errorf("error should mention STORM_MODE_THRESHOLD, got: %v", err)
	}
}

// TestAnalysisPolicy_AllModels_OnlyDefault verifies that AllModels returns only
// the DefaultModel when no overrides are configured. AllModels is called at
// startup by main.go to pre-materialize Prometheus token series; a missing or
// duplicated model entry would leave a series permanently absent or doubled.
func TestAnalysisPolicy_AllModels_OnlyDefault(t *testing.T) {
	p := &AnalysisPolicy{DefaultModel: "claude-sonnet-4-6"}
	got := p.AllModels()
	if len(got) != 1 {
		t.Fatalf("AllModels: got %v, want exactly 1 entry", got)
	}
	if got[0] != "claude-sonnet-4-6" {
		t.Errorf("AllModels[0] = %q, want claude-sonnet-4-6", got[0])
	}
}

// TestAnalysisPolicy_AllModels_IncludesOverrides verifies that AllModels returns
// both the DefaultModel and every distinct model referenced in ModelOverrides.
func TestAnalysisPolicy_AllModels_IncludesOverrides(t *testing.T) {
	p := &AnalysisPolicy{
		DefaultModel: "claude-sonnet-4-6",
		ModelOverrides: map[Severity]string{
			SeverityCritical: "claude-opus-4-6",
			SeverityWarning:  "claude-haiku-4-5",
		},
	}
	got := p.AllModels()
	if len(got) != 3 {
		t.Fatalf("AllModels: got %v, want 3 distinct entries", got)
	}
	inResult := func(model string) bool {
		for _, m := range got {
			if m == model {
				return true
			}
		}
		return false
	}
	for _, want := range []string{"claude-sonnet-4-6", "claude-opus-4-6", "claude-haiku-4-5"} {
		if !inResult(want) {
			t.Errorf("AllModels missing %q; got %v", want, got)
		}
	}
}

// TestAnalysisPolicy_AllModels_DeduplicatesOverrideEqualToDefault verifies that
// when an override model equals the DefaultModel, AllModels deduplicates it so
// each model appears exactly once. Without this, MaterializeClaudeTokensForModels
// would call WithLabelValues twice for the same model, creating no duplicate
// series (Prometheus counters it as one), but the intent is to return a set.
func TestAnalysisPolicy_AllModels_DeduplicatesOverrideEqualToDefault(t *testing.T) {
	p := &AnalysisPolicy{
		DefaultModel: "claude-sonnet-4-6",
		ModelOverrides: map[Severity]string{
			SeverityCritical: "claude-sonnet-4-6", // same as default
			SeverityWarning:  "claude-haiku-4-5",
		},
	}
	got := p.AllModels()
	if len(got) != 2 {
		t.Fatalf("AllModels: got %v, want 2 entries (dedup expected)", got)
	}
	seen := map[string]int{}
	for _, m := range got {
		seen[m]++
	}
	for m, count := range seen {
		if count > 1 {
			t.Errorf("AllModels: model %q appears %d times, want 1", m, count)
		}
	}
}

// TestAnalysisPolicy_AllModels_SkipsEmptyDefault verifies that an empty
// DefaultModel is not included in the result. This guards against a regression
// where MaterializeClaudeTokensForModels is called with an empty-string model
// label, which would create a metric series with model="" in the Prometheus
// output and pollute dashboards.
func TestAnalysisPolicy_AllModels_SkipsEmptyDefault(t *testing.T) {
	p := &AnalysisPolicy{
		DefaultModel: "",
		ModelOverrides: map[Severity]string{
			SeverityCritical: "claude-opus-4-6",
		},
	}
	got := p.AllModels()
	for _, m := range got {
		if m == "" {
			t.Errorf("AllModels returned empty-string model; got %v", got)
		}
	}
	if len(got) != 1 || got[0] != "claude-opus-4-6" {
		t.Errorf("AllModels: got %v, want [claude-opus-4-6]", got)
	}
}

// TestAnalysisPolicy_AllModels_DefaultModelIsFirst verifies that the DefaultModel
// is always the first entry in AllModels. main.go calls AllModels at startup and
// logs no explicit ordering guarantee, but the implementation adds DefaultModel
// first and this invariant must not silently break; a change that moves
// DefaultModel to a random position would make startup logs harder to read and
// could confuse future callers that rely on stable ordering.
func TestAnalysisPolicy_AllModels_DefaultModelIsFirst(t *testing.T) {
	p := &AnalysisPolicy{
		DefaultModel: "claude-sonnet-4-6",
		ModelOverrides: map[Severity]string{
			SeverityCritical: "claude-opus-4-6",
		},
	}
	got := p.AllModels()
	if len(got) == 0 {
		t.Fatal("AllModels returned empty slice")
	}
	if got[0] != "claude-sonnet-4-6" {
		t.Errorf("AllModels[0] = %q, want DefaultModel %q first", got[0], "claude-sonnet-4-6")
	}
}
