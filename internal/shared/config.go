package shared

import (
	"fmt"
	"os"
	"strconv"
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

// RequireEnv returns the value of the environment variable key,
// or an error if it is not set or empty.
func RequireEnv(key string) (string, error) {
	v := os.Getenv(key)
	if v == "" {
		return "", fmt.Errorf("%s is required but not set", key)
	}
	return v, nil
}
