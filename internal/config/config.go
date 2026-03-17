package config

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
)

func RequiredSecret(envName string) ([]byte, error) {
	value, ok, err := lookupSecret(envName)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%s is required", envName)
	}
	return value, nil
}

func OptionalSecret(envName string) ([]byte, bool, error) {
	return lookupSecret(envName)
}

func lookupSecret(envName string) ([]byte, bool, error) {
	raw, ok := os.LookupEnv(envName)
	if !ok {
		return nil, false, nil
	}
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, false, fmt.Errorf("%s is set but empty", envName)
	}
	return []byte(value), true, nil
}

func DeriveKey(secret []byte, purpose string, size int) ([]byte, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("secret for %s is empty", purpose)
	}
	return hkdf.Key(sha256.New, secret, nil, purpose, size)
}

func Bool(envName string, defaultValue bool) bool {
	raw, ok := os.LookupEnv(envName)
	if !ok {
		return defaultValue
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return defaultValue
	}
}
