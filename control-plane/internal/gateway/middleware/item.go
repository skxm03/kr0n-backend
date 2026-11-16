package middleware

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// MiddlewareItem represents a declared middleware item in YAML, which can be either
// a simple name (e.g. "- request_id") or a mapped configuration (e.g. "- rate_limit: { requests: 10 }").
type MiddlewareItem struct {
	Name   string         `yaml:"name"`
	Config map[string]any `yaml:"config"`
}

// UnmarshalYAML implements custom decoding to support both string and map-of-one formats.
func (m *MiddlewareItem) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		m.Name = strings.TrimSpace(node.Value)
		m.Config = nil
		return nil
	}

	if node.Kind == yaml.MappingNode {
		// Try single-entry map: rate_limit: { requests: 100, window: 1m }
		var singleEntry map[string]map[string]any
		if err := node.Decode(&singleEntry); err == nil && len(singleEntry) == 1 {
			for k, v := range singleEntry {
				m.Name = strings.TrimSpace(k)
				m.Config = v
				return nil
			}
		}

		// Also support single-entry with empty or scalar config
		var anyEntry map[string]any
		if err := node.Decode(&anyEntry); err == nil && len(anyEntry) == 1 {
			for k, v := range anyEntry {
				m.Name = strings.TrimSpace(k)
				if cfgMap, ok := v.(map[string]any); ok {
					m.Config = cfgMap
				} else if v != nil {
					m.Config = map[string]any{"value": v}
				}
				return nil
			}
		}

		// Try explicit name/config fields
		var explicit struct {
			Name   string         `yaml:"name"`
			Config map[string]any `yaml:"config"`
		}
		if err := node.Decode(&explicit); err == nil && explicit.Name != "" {
			m.Name = strings.TrimSpace(explicit.Name)
			m.Config = explicit.Config
			return nil
		}

		return fmt.Errorf("invalid middleware item mapping at line %d (must be 'name: { ... }' or '{ name: ..., config: ... }')", node.Line)
	}

	return fmt.Errorf("unexpected yaml node kind %d for middleware item at line %d", node.Kind, node.Line)
}
