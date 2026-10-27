package config

import (
	"fmt"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

type Config struct {
	DatabaseURL                    string        `env:"DATABASE_URL"`
	AuthGRPCAddr                   string        `env:"AUTH_GRPC_ADDR"`
	Env                            string        `env:"KR0N_ENV"`
	JWTPrivateKey                  string        `env:"JWT_PRIVATE_KEY"`
	JWTKeyID                       string        `env:"JWT_KEY_ID"`
	JWTIssuer                      string        `env:"JWT_ISSUER"`
	JWTAudience                    string        `env:"JWT_AUDIENCE"`
	AccessTokenLifetime            time.Duration `env:"ACCESS_TOKEN_LIFETIME"`
	RefreshTokenLifetime           time.Duration `env:"REFRESH_TOKEN_LIFETIME"`
	EmailVerificationTokenLifetime time.Duration `env:"EMAIL_VERIFICATION_TOKEN_LIFETIME"`
	PasswordResetTokenLifetime     time.Duration `env:"PASSWORD_RESET_TOKEN_LIFETIME"`
	RequireVerifiedEmail           bool          `env:"REQUIRE_VERIFIED_EMAIL"`
	RabbitMQURL                    string        `env:"RABBITMQ_URL"`
	EmailQueueName                 string        `env:"EMAIL_QUEUE_NAME"`
	GitHubClientID                 string        `env:"GITHUB_CLIENT_ID"`
	GitHubClientSecret             string        `env:"GITHUB_CLIENT_SECRET"`
	GitHubRedirectURL              string        `env:"GITHUB_REDIRECT_URL"`
	AuthGRPCTLSCertFile            string        `env:"AUTH_GRPC_TLS_CERT_FILE"`
	AuthGRPCTLSKeyFile             string        `env:"AUTH_GRPC_TLS_KEY_FILE"`
	AuthGRPCClientCAFile           string        `env:"AUTH_GRPC_CLIENT_CA_FILE"`
	AuthGRPCAllowedClients         []string      `env:"AUTH_GRPC_ALLOWED_CLIENTS"`
	AuthServiceToken               string        `env:"AUTH_SERVICE_TOKEN"`
}

func LoadConfig() (*Config, error) {
	_ = godotenv.Load()

	var cfg Config
	if err := env.Parse(&cfg); err != nil {
		return nil, fmt.Errorf("parse config environment variables: %w", err)
	}

	return &cfg, nil
}
