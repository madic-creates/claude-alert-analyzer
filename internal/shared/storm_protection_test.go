package shared

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"
)

// alwaysFailPublisher implements Publisher and always returns the same error.
// Used to drive NotifyAggregator.Stop's final flush into returning a non-nil
// error so the StormProtection.Stop slog.Warn branches can be exercised.
type alwaysFailPublisher struct{ err error }

func (p *alwaysFailPublisher) Name() string { return "alwaysfail" }
func (p *alwaysFailPublisher) Publish(_ context.Context, _, _, _ string) error {
	return p.err
}

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

// TestStormProtection_Stop_LogsWarnOnAggregatorError verifies the two
// slog.Warn branches in StormProtection.Stop fire when an aggregator's
// final flush returns an error. Without this test the storm/breaker error
// branches sit at 0% coverage and a regression could turn them into silent
// failures during shutdown.
func TestStormProtection_Stop_LogsWarnOnAggregatorError(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	old := slog.Default()
	slog.SetDefault(slog.New(handler))
	t.Cleanup(func() { slog.SetDefault(old) })

	fail := &alwaysFailPublisher{err: errors.New("publish boom")}
	// Interval=time.Hour keeps the periodic timer from firing before Stop,
	// so the buffered title survives to the shutdown flush where it will
	// trigger PublishAll's error path.
	storm := NewNotifyAggregator([]Publisher{fail}, time.Hour, "storm %d", "4", newDropsCounter())
	breaker := NewNotifyAggregator([]Publisher{fail}, time.Hour, "breaker %d", "5", newDropsCounter())
	if storm == nil || breaker == nil {
		t.Fatal("expected non-nil aggregators")
	}
	sp := &StormProtection{StormNotify: storm, BreakerNotify: breaker}

	if !sp.StormNotify.Add("storm-title") {
		t.Fatal("storm Add() returned false")
	}
	if !sp.BreakerNotify.Add("breaker-title") {
		t.Fatal("breaker Add() returned false")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	sp.Stop(ctx)

	foundStorm, foundBreaker := false, false
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		switch rec["msg"] {
		case "storm aggregator stop returned error":
			foundStorm = true
		case "breaker aggregator stop returned error":
			foundBreaker = true
		}
	}
	if !foundStorm {
		t.Errorf("storm aggregator slog.Warn not emitted; log output:\n%s", buf.String())
	}
	if !foundBreaker {
		t.Errorf("breaker aggregator slog.Warn not emitted; log output:\n%s", buf.String())
	}
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
		{"storm interval zero", "STORM_MODE_NOTIFY_INTERVAL", "0s", "STORM_MODE_NOTIFY_INTERVAL"},
		{"storm interval negative", "STORM_MODE_NOTIFY_INTERVAL", "-1s", "STORM_MODE_NOTIFY_INTERVAL"},
		{"breaker interval invalid", "CIRCUIT_BREAKER_NOTIFY_INTERVAL", "notaduration", "CIRCUIT_BREAKER_NOTIFY_INTERVAL"},
		{"breaker interval zero", "CIRCUIT_BREAKER_NOTIFY_INTERVAL", "0s", "CIRCUIT_BREAKER_NOTIFY_INTERVAL"},
		{"breaker interval negative", "CIRCUIT_BREAKER_NOTIFY_INTERVAL", "-30s", "CIRCUIT_BREAKER_NOTIFY_INTERVAL"},
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

// TestLoadStormProtectionConfig_ExactBoundaries pins the inclusive endpoints of
// the ParseIntEnv range guards for the CIRCUIT_BREAKER_* integer parameters.
//
// The error-case tests (TestLoadStormProtectionConfig_EnvVarErrors) confirm that
// out-of-range values (0, 3601, 101) are rejected. They do NOT verify the exact
// valid endpoints: 1, 3600, 100. A mutation that shifts the internal
// ParseIntEnv min from 1 to 2, or the max from 3600 to 3599, would silently
// reject a valid operator configuration with no test failure. These five sub-tests
// close that gap — one per boundary that was previously untested.
func TestLoadStormProtectionConfig_ExactBoundaries(t *testing.T) {
	cases := []struct {
		name  string
		key   string
		value string
	}{
		{"open_seconds exact min (1)", "CIRCUIT_BREAKER_OPEN_SECONDS", "1"},
		{"open_seconds exact max (3600)", "CIRCUIT_BREAKER_OPEN_SECONDS", "3600"},
		{"probe_seconds exact min (1)", "CIRCUIT_BREAKER_MAX_PROBE_SECONDS", "1"},
		{"probe_seconds exact max (3600)", "CIRCUIT_BREAKER_MAX_PROBE_SECONDS", "3600"},
		{"threshold exact max (100)", "CIRCUIT_BREAKER_THRESHOLD", "100"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stormProtectionUnsetAll(t)
			t.Setenv(tc.key, tc.value)
			if _, err := LoadStormProtectionConfig(); err != nil {
				t.Errorf("%s=%s should be accepted, got error: %v", tc.key, tc.value, err)
			}
		})
	}
}
