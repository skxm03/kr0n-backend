package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

// Config holds environment configuration for the stateless downstream audit consumer daemon.
type Config struct {
	Env              string        `env:"KR0N_ENV"`
	DatabaseURL      string        `env:"DATABASE_URL"`
	AuditRabbitMQURL string        `env:"AUDIT_RABBITMQ_URL"`
	FallbackRMQURL   string        `env:"RABBITMQ_URL"`
	ExchangeName     string        `env:"AUDIT_EXCHANGE_NAME"`
	QueueName        string        `env:"AUDIT_QUEUE_NAME"`
	BatchSize        int           `env:"AUDIT_BATCH_SIZE"`
	BatchTimeout     time.Duration `env:"AUDIT_BATCH_TIMEOUT"`
	MaxRetries       int           `env:"AUDIT_MAX_RETRIES"`
	RetryBackoff     time.Duration `env:"AUDIT_RETRY_BACKOFF"`
	Sinks            []string      `env:"AUDIT_SINKS" envSeparator:","`
}

// EffectiveRabbitMQURL returns AUDIT_RABBITMQ_URL if set, falling back to RABBITMQ_URL.
func (c *Config) EffectiveRabbitMQURL() string {
	if url := strings.TrimSpace(c.AuditRabbitMQURL); url != "" {
		return url
	}
	return strings.TrimSpace(c.FallbackRMQURL)
}

// LoadConfig loads environment variables into Config.
func LoadConfig() (*Config, error) {
	_ = godotenv.Load()

	var cfg Config
	if err := env.Parse(&cfg); err != nil {
		return nil, fmt.Errorf("parse audit config environment variables: %w", err)
	}

	return &cfg, nil
}
