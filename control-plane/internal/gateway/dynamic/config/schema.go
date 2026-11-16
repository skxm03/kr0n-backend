package config

import (
	"time"

	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
)

// GatewayConfig represents the top-level YAML configuration structure.
type GatewayConfig struct {
	Gateway            ServerConfig                         `yaml:"gateway"`
	MiddlewareProfiles map[string][]middleware.MiddlewareItem `yaml:"middleware_profiles"`
	Services           map[string]ServiceConfig             `yaml:"services"`
}

// ServerConfig defines the gateway's HTTP listener, global settings, and global middleware.
type ServerConfig struct {
	HTTPAddr     string                      `yaml:"http_addr"`
	ReadTimeout  time.Duration               `yaml:"read_timeout"`
	WriteTimeout time.Duration               `yaml:"write_timeout"`
	IdleTimeout  time.Duration               `yaml:"idle_timeout"`
	MaxBodyBytes int64                       `yaml:"max_body_bytes"`
	Middleware   []middleware.MiddlewareItem `yaml:"middleware"` // Global middleware chain
}

// ServiceConfig defines an upstream gRPC service connection, timeouts, groups, and exposed endpoints.
type ServiceConfig struct {
	Address        string                      `yaml:"address"`
	Enabled        *bool                       `yaml:"enabled"`         // Optional, defaults to true
	AutoMount      *bool                       `yaml:"auto_mount"`      // Optional, defaults to true: auto-mounts registered service endpoints
	DefaultProfile string                      `yaml:"default_profile"` // Fallback profile if an endpoint does not match any group
	Timeout        time.Duration               `yaml:"timeout"`
	TLS            TLSConfig                   `yaml:"tls"`
	ServiceToken   string                      `yaml:"service_token"`
	Middleware     []middleware.MiddlewareItem `yaml:"middleware"` // Service-level middleware chain
	Groups         map[string]GroupConfig      `yaml:"groups"`     // URL group middleware
	Endpoints      []EndpointConfig            `yaml:"endpoints"`
}

// IsEnabled returns true if the service is explicitly enabled or enabled is nil (default).
func (s ServiceConfig) IsEnabled() bool {
	if s.Enabled == nil {
		return true
	}
	return *s.Enabled
}

// IsAutoMount returns true if AutoMount is nil (default) or explicitly set to true.
func (s ServiceConfig) IsAutoMount() bool {
	if s.AutoMount == nil {
		return true
	}
	return *s.AutoMount
}

// GroupConfig defines URL pattern-matching rules and the middleware applied to matching endpoints.
type GroupConfig struct {
	Match      []MatchRule                 `yaml:"match"`
	Use        []string                    `yaml:"use"`        // Profile names
	Middleware []middleware.MiddlewareItem `yaml:"middleware"` // Group-specific middleware items
}

// MatchRule defines a URL path matching condition.
type MatchRule struct {
	Path    string   `yaml:"path"`
	Type    string   `yaml:"type"`    // "exact", "prefix", "template"
	Methods []string `yaml:"methods"` // Optional method filter (empty = any method)
}

// TLSConfig defines transport security parameters for connecting to an upstream gRPC service.
type TLSConfig struct {
	Enabled    bool   `yaml:"enabled"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	CAFile     string `yaml:"ca_file"`
	ServerName string `yaml:"server_name"`
}

// EndpointConfig defines an explicitly allowed HTTP endpoint mapped to the upstream gRPC service.
type EndpointConfig struct {
	Path       string                      `yaml:"path"`
	Method     string                      `yaml:"method"`
	Timeout    time.Duration               `yaml:"timeout"`
	Use        []string                    `yaml:"use"`        // Profile names
	Middleware []middleware.MiddlewareItem `yaml:"middleware"` // Endpoint-specific middleware items
}
