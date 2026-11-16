package config

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

var envVarPattern = regexp.MustCompile(`\$\{([a-zA-Z_][a-zA-Z0-9_]*)(?::-([^}]*))?\}`)

// ExpandEnvWithDefaults expands variables in the form ${VAR} or ${VAR:-default}.
func ExpandEnvWithDefaults(s string) string {
	return envVarPattern.ReplaceAllStringFunc(s, func(match string) string {
		sub := envVarPattern.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		varName := sub[1]
		defaultVal := ""
		if len(sub) >= 3 {
			defaultVal = sub[2]
		}
		val, found := os.LookupEnv(varName)
		if found && val != "" {
			return val
		}
		return defaultVal
	})
}

// LoadConfig parses a GatewayConfig from raw YAML bytes, expands environment variables,
// applies default values, and validates the configuration.
func LoadConfig(data []byte) (*GatewayConfig, error) {
	expanded := ExpandEnvWithDefaults(string(data))

	var cfg GatewayConfig
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("yaml unmarshal error: %w", err)
	}

	ApplyDefaults(&cfg)

	if err := Validate(&cfg); err != nil {
		return nil, fmt.Errorf("config validation error: %w", err)
	}

	return &cfg, nil
}

// LoadConfigFile reads a YAML configuration file from disk, parses, applies defaults, and validates it.
func LoadConfigFile(path string) (*GatewayConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read gateway config file %q: %w", path, err)
	}
	return LoadConfig(data)
}
