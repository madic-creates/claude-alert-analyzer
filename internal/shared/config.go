package shared

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// EnvOrDefault returns the value of the environment variable key,
// or fallback if the variable is not set or empty.
func EnvOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ParseIntEnv reads an integer environment variable with range validation.
// Returns an error if the value is not a valid integer or falls outside [min, max].
func ParseIntEnv(key, fallback string, min, max int) (int, error) {
	raw := EnvOrDefault(key, fallback)
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s=%q: not a valid integer", key, raw)
	}
	if v < min || v > max {
		return 0, fmt.Errorf("%s=%d: must be between %d and %d", key, v, min, max)
	}
	return v, nil
}

// ParseBoolEnv reads a boolean environment variable using strconv.ParseBool
// semantics: "1", "t", "T", "TRUE", "true", "True" are true; "0", "f", "F",
// "FALSE", "false", "False" are false. Unset or empty returns fallback.
// An unrecognised value returns an error so misconfiguration fails fast at
// startup rather than silently coercing to a (possibly unintended) bool.
//
// This replaces ad-hoc patterns like EnvOrDefault(key, "true") == "true",
// which silently treat "TRUE"/"1"/"yes" as the negative case — typically
// the opposite of the operator's intent.
func ParseBoolEnv(key string, fallback bool) (bool, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s=%q: not a valid boolean (expected 1/0, true/false, t/f, TRUE/FALSE)", key, raw)
	}
	return v, nil
}

// RequireEnv returns the value of the environment variable key,
// or an error if it is not set or empty.
func RequireEnv(key string) (string, error) {
	v := os.Getenv(key)
	if v == "" {
		return "", fmt.Errorf("%s is required but not set", key)
	}
	return v, nil
}

// ParseDurationEnv reads a Go duration env var (e.g. "6h", "90m"). Unset or
// empty returns fallback. An unparseable value returns an error so
// misconfiguration fails fast at startup.
func ParseDurationEnv(key string, fallback time.Duration) (time.Duration, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s=%q: not a valid duration (e.g. 6h, 90m, 30s)", key, raw)
	}
	return d, nil
}
