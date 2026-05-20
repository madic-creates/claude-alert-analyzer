package shared

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// stormProtectionUnsetAll clears every env var LoadStormProtectionConfig
// reads so each test starts from a clean baseline. t.Setenv inside individual
// tests overrides this on a per-test basis.
func stormProtectionUnsetAll(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"CIRCUIT_BREAKER_THRESHOLD",
		"CIRCUIT_BREAKER_OPEN_SECONDS",
		"CIRCUIT_BREAKER_MAX_PROBE_SECONDS",
		"STORM_MODE_NOTIFY_INTERVAL",
		"CIRCUIT_BREAKER_NOTIFY_INTERVAL",
	} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
}

func TestLoadStormProtectionConfig_Defaults(t *testing.T) {
	stormProtectionUnsetAll(t)
	cfg, err := LoadStormProtectionConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.BreakerThreshold != 0 {
		t.Errorf("BreakerThreshold: got %d, want 0", cfg.BreakerThreshold)
	}
	if cfg.BreakerOpen != 60*time.Second {
		t.Errorf("BreakerOpen: got %v, want 60s", cfg.BreakerOpen)
	}
	if cfg.BreakerMaxProbe != 60*time.Second {
		t.Errorf("BreakerMaxProbe: got %v, want 60s", cfg.BreakerMaxProbe)
	}
	if cfg.StormNotifyInterval != 60*time.Second {
		t.Errorf("StormNotifyInterval: got %v, want 60s", cfg.StormNotifyInterval)
	}
	if cfg.BreakerNotifyInterval != 300*time.Second {
		t.Errorf("BreakerNotifyInterval: got %v, want 300s", cfg.BreakerNotifyInterval)
	}
}

func TestStormProtectionConfig_Build_ThresholdZeroDisablesBreaker(t *testing.T) {
	stormProtectionUnsetAll(t)
	cfg, err := LoadStormProtectionConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sp := cfg.Build([]Publisher{&aggFakePublisher{}}, NewAlertMetrics(nil))
	if sp == nil {
		t.Fatal("got nil StormProtection")
	}
	if sp.Breaker != nil {
		t.Error("expected nil Breaker when threshold=0")
	}
	if sp.StormNotify == nil {
		t.Error("expected non-nil StormNotify")
	}
	if sp.BreakerNotify == nil {
		t.Error("expected non-nil BreakerNotify")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	sp.Stop(ctx)
}

func TestStormProtectionConfig_Build_ThresholdEnablesBreaker(t *testing.T) {
	stormProtectionUnsetAll(t)
	t.Setenv("CIRCUIT_BREAKER_THRESHOLD", "3")
	cfg, err := LoadStormProtectionConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sp := cfg.Build([]Publisher{&aggFakePublisher{}}, NewAlertMetrics(nil))
	if sp.Breaker == nil {
		t.Fatal("expected non-nil Breaker when threshold=3")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	sp.Stop(ctx)
}

func TestStormProtection_StopNil(t *testing.T) {
	// Calling Stop on a nil receiver must not panic — Stop is meant to be
	// deferred at the call site without a presence guard.
	var sp *StormProtection
	sp.Stop(context.Background())
}

func TestLoadStormProtectionConfig_EnvVarErrors(t *testing.T) {
	cases := []struct {
		name        string
		envKey      string
		envVal      string
		wantInError string
	}{
		{"threshold out of range", "CIRCUIT_BREAKER_THRESHOLD", "101", "CIRCUIT_BREAKER_THRESHOLD"},
		{"threshold non-numeric", "CIRCUIT_BREAKER_THRESHOLD", "abc", "CIRCUIT_BREAKER_THRESHOLD"},
		{"open_seconds zero", "CIRCUIT_BREAKER_OPEN_SECONDS", "0", "CIRCUIT_BREAKER_OPEN_SECONDS"},
		{"open_seconds too large", "CIRCUIT_BREAKER_OPEN_SECONDS", "3601", "CIRCUIT_BREAKER_OPEN_SECONDS"},
		{"probe_seconds zero", "CIRCUIT_BREAKER_MAX_PROBE_SECONDS", "0", "CIRCUIT_BREAKER_MAX_PROBE_SECONDS"},
		{"storm interval invalid", "STORM_MODE_NOTIFY_INTERVAL", "notaduration", "STORM_MODE_NOTIFY_INTERVAL"},
		{"breaker interval invalid", "CIRCUIT_BREAKER_NOTIFY_INTERVAL", "notaduration", "CIRCUIT_BREAKER_NOTIFY_INTERVAL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stormProtectionUnsetAll(t)
			t.Setenv(tc.envKey, tc.envVal)
			_, err := LoadStormProtectionConfig()
			if err == nil {
				t.Fatalf("expected error for %s=%q", tc.envKey, tc.envVal)
			}
			if !strings.Contains(err.Error(), tc.wantInError) {
				t.Errorf("error %q does not mention %q (required so main.go's slog.Error surfaces the offending var for the cmd/*/main_test.go grep)", err.Error(), tc.wantInError)
			}
		})
	}
}
