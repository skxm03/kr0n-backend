package config

import (
	"fmt"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

type Config struct {
	Env          string        `env:"KR0N_ENV"`
	RabbitMQURL  string        `env:"RABBITMQ_URL"`
	QueueName    string        `env:"EMAIL_QUEUE_NAME"`
	BatchSize    int           `env:"EMAIL_BATCH_SIZE"`
	BatchTimeout time.Duration `env:"EMAIL_BATCH_TIMEOUT"`
	BatchWorkers int           `env:"EMAIL_BATCH_WORKERS"`
	SMTPAddr     string        `env:"SMTP_ADDR"`
	SMTPFrom     string        `env:"SMTP_FROM"`
	SMTPUsername string        `env:"SMTP_USERNAME"`
	SMTPPassword string        `env:"SMTP_PASSWORD"`
	SMTPTimeout  time.Duration `env:"SMTP_TIMEOUT"`
}

func LoadConfig() (*Config, error) {
	_ = godotenv.Load()

	var cfg Config
	if err := env.Parse(&cfg); err != nil {
		return nil, fmt.Errorf("parse config environment variables: %w", err)
	}

	return &cfg, nil
}
