package config

import (
	"fmt"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

// Config holds configuration for the Service Manager microservice.
type Config struct {
	Env                          string   `env:"KR0N_ENV" envDefault:"dev"`
	DatabaseURL                  string   `env:"DATABASE_URL"`
	GRPCAddr                     string   `env:"SERVICEMANAGER_GRPC_ADDR" envDefault:"127.0.0.1:50053"`
	AuditRabbitMQURL             string   `env:"AUDIT_RABBITMQ_URL"`
	AuditExchangeName            string   `env:"AUDIT_EXCHANGE_NAME" envDefault:"audit.events"`
	TLSCertFile                  string   `env:"SERVICEMANAGER_GRPC_TLS_CERT_FILE"`
	TLSKeyFile                   string   `env:"SERVICEMANAGER_GRPC_TLS_KEY_FILE"`
	ClientCAFile                 string   `env:"SERVICEMANAGER_GRPC_CLIENT_CA_FILE"`
	FallbackClientCAFile         string   `env:"AUTH_GRPC_CLIENT_CA_FILE"`
	AllowedClients               []string `env:"SERVICEMANAGER_GRPC_ALLOWED_CLIENTS" envDefault:"kr0n-gateway,gateway"`
}

// EffectiveClientCAFile returns SERVICEMANAGER_GRPC_CLIENT_CA_FILE if set, falling back to AUTH_GRPC_CLIENT_CA_FILE.
func (c *Config) EffectiveClientCAFile() string {
	if c.ClientCAFile != "" {
		return c.ClientCAFile
	}
	return c.FallbackClientCAFile
}

// LoadConfig parses environment variables into Config.
func LoadConfig() (*Config, error) {
	_ = godotenv.Load()

	var cfg Config
	if err := env.Parse(&cfg); err != nil {
		return nil, fmt.Errorf("parse servicemanager config environment variables: %w", err)
	}
	return &cfg, nil
}
