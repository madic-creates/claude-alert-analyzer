package shared

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// StormProtectionConfig holds the parsed env-var values for the CircuitBreaker
// and the storm/breaker NotifyAggregators. Splitting validation (LoadStormProtectionConfig)
// from construction (Build) lets callers fail fast on misconfiguration before
// touching environment-specific resources (InClusterConfig, Prometheus registry).
type StormProtectionConfig struct {
	BreakerThreshold      int
	BreakerOpen           time.Duration
	BreakerMaxProbe       time.Duration
	StormNotifyInterval   time.Duration
	BreakerNotifyInterval time.Duration
}

// StormProtection bundles the CircuitBreaker plus the storm/breaker
// NotifyAggregators. Both main.go entry points construct an identical bundle
// (only the publisher set differs), so this consolidates constructor wiring
// and shutdown sequence in one place.
type StormProtection struct {
	Breaker       *CircuitBreaker
	StormNotify   *NotifyAggregator
	BreakerNotify *NotifyAggregator
}

// LoadStormProtectionConfig reads the CIRCUIT_BREAKER_* and *_NOTIFY_INTERVAL
// env vars and returns a validated config. Errors carry the offending env-var
// name so callers can surface it via slog.Error and the startup error-text
// tests in cmd/*/main_test.go continue to pass.
//
// This is the early-validation entry point: call it before any environment-
// specific setup (k8s InClusterConfig, Prometheus registry) so misconfigured
// env vars produce a fast, clear startup error instead of being masked by a
// later, less informative failure.
func LoadStormProtectionConfig() (StormProtectionConfig, error) {
	breakerThreshold, err := ParseIntEnv("CIRCUIT_BREAKER_THRESHOLD", "0", 0, 100)
	if err != nil {
		return StormProtectionConfig{}, err
	}
	breakerOpenSecs, err := ParseIntEnv("CIRCUIT_BREAKER_OPEN_SECONDS", "60", 1, 3600)
	if err != nil {
		return StormProtectionConfig{}, err
	}
	breakerProbeSecs, err := ParseIntEnv("CIRCUIT_BREAKER_MAX_PROBE_SECONDS", "60", 1, 3600)
	if err != nil {
		return StormProtectionConfig{}, err
	}
	stormNotifyInterval, err := time.ParseDuration(EnvOrDefault("STORM_MODE_NOTIFY_INTERVAL", "60s"))
	if err != nil {
		return StormProtectionConfig{}, fmt.Errorf("invalid STORM_MODE_NOTIFY_INTERVAL: %w", err)
	}
	// NewNotifyAggregator short-circuits to nil when interval <= 0, which would
	// silently drop every storm-mode notification at runtime without any startup
	// error. Reject non-positive durations here so misconfiguration fails fast
	// with a clear message — matching the min=1 bound applied to the integer-
	// second env vars (CIRCUIT_BREAKER_OPEN_SECONDS, CIRCUIT_BREAKER_MAX_PROBE_SECONDS).
	if stormNotifyInterval <= 0 {
		return StormProtectionConfig{}, fmt.Errorf("invalid STORM_MODE_NOTIFY_INTERVAL: must be positive, got %v", stormNotifyInterval)
	}
	breakerNotifyInterval, err := time.ParseDuration(EnvOrDefault("CIRCUIT_BREAKER_NOTIFY_INTERVAL", "300s"))
	if err != nil {
		return StormProtectionConfig{}, fmt.Errorf("invalid CIRCUIT_BREAKER_NOTIFY_INTERVAL: %w", err)
	}
	if breakerNotifyInterval <= 0 {
		return StormProtectionConfig{}, fmt.Errorf("invalid CIRCUIT_BREAKER_NOTIFY_INTERVAL: must be positive, got %v", breakerNotifyInterval)
	}
	return StormProtectionConfig{
		BreakerThreshold:      breakerThreshold,
		BreakerOpen:           time.Duration(breakerOpenSecs) * time.Second,
		BreakerMaxProbe:       time.Duration(breakerProbeSecs) * time.Second,
		StormNotifyInterval:   stormNotifyInterval,
		BreakerNotifyInterval: breakerNotifyInterval,
	}, nil
}

// Build constructs the CircuitBreaker plus the storm/breaker NotifyAggregators
// from a validated config. Designed for use after the caller has constructed
// the Prometheus metrics and publisher set.
func (c StormProtectionConfig) Build(publishers []Publisher, metrics *AlertMetrics) *StormProtection {
	breaker := NewCircuitBreaker(c.BreakerThreshold, c.BreakerOpen, c.BreakerMaxProbe, time.Now)
	stormNotify := NewNotifyAggregator(
		publishers,
		c.StormNotifyInterval,
		"Storm-mode active: %d alerts in last interval",
		"4",
		metrics.AggregatorDropsCounter("storm"),
	)
	breakerNotify := NewNotifyAggregator(
		publishers,
		c.BreakerNotifyInterval,
		"API rate-limited: %d alerts pending manual review",
		"5",
		metrics.AggregatorDropsCounter("breaker"),
	)
	return &StormProtection{
		Breaker:       breaker,
		StormNotify:   stormNotify,
		BreakerNotify: breakerNotify,
	}
}

// Stop stops both NotifyAggregators with the supplied context, logging any
// per-aggregator error via slog.Warn. Designed for use in a defer block at
// the call site so shutdown is symmetric across both binaries.
func (s *StormProtection) Stop(ctx context.Context) {
	if s == nil {
		return
	}
	if s.StormNotify != nil {
		if err := s.StormNotify.Stop(ctx); err != nil {
			slog.Warn("storm aggregator stop returned error", "error", err)
		}
	}
	if s.BreakerNotify != nil {
		if err := s.BreakerNotify.Stop(ctx); err != nil {
			slog.Warn("breaker aggregator stop returned error", "error", err)
		}
	}
}
