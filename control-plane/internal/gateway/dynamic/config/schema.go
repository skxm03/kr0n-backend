package config

import "time"

// GatewayConfig represents the top-level YAML configuration structure.
type GatewayConfig struct {
	Gateway  ServerConfig             `yaml:"gateway"`
	Services map[string]ServiceConfig `yaml:"services"`
}

// ServerConfig defines the gateway's HTTP listener and global connection settings.
type ServerConfig struct {
	HTTPAddr     string        `yaml:"http_addr"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
	IdleTimeout  time.Duration `yaml:"idle_timeout"`
	MaxBodyBytes int64         `yaml:"max_body_bytes"`
}

// ServiceConfig defines an upstream gRPC service connection, timeouts, and exposed endpoints.
type ServiceConfig struct {
	Address      string           `yaml:"address"`
	Enabled      *bool            `yaml:"enabled"` // Optional, defaults to true
	Timeout      time.Duration    `yaml:"timeout"`
	TLS          TLSConfig        `yaml:"tls"`
	ServiceToken string           `yaml:"service_token"`
	Endpoints    []EndpointConfig `yaml:"endpoints"`
}

// IsEnabled returns true if the service is explicitly enabled or enabled is nil (default).
func (s ServiceConfig) IsEnabled() bool {
	if s.Enabled == nil {
		return true
	}
	return *s.Enabled
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
	Path    string        `yaml:"path"`
	Method  string        `yaml:"method"`
	Timeout time.Duration `yaml:"timeout"`
}
