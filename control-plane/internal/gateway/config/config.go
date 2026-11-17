package config

import (
	"fmt"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

type Config struct {
	Env               string   `env:"KR0N_ENV" envDefault:"dev"`
	GatewayConfigPath string   `env:"GATEWAY_CONFIG_PATH" envDefault:"gateway.yaml"`
	GatewayHTTPAddr   string   `env:"GATEWAY_HTTP_ADDR"`
	AuthGRPCAddr      string   `env:"AUTH_GRPC_ADDR"`
	JWTPublicKeys     string   `env:"JWT_PUBLIC_KEYS"`
	JWTKeyID          string   `env:"JWT_KEY_ID" envDefault:"k1"`
	JWTIssuer         string   `env:"JWT_ISSUER" envDefault:"kr0n-auth"`
	JWTAudience       string   `env:"JWT_AUDIENCE" envDefault:"kr0n-api"`
	RedisAddr         string   `env:"REDIS_ADDR" envDefault:"localhost:6379"`
	TrustedProxyCIDRs []string `env:"TRUSTED_PROXY_CIDRS"`

	// Upstream Auth TLS/Token optional overrides
	AuthGRPCTLSCAFile   string `env:"AUTH_GRPC_TLS_CA_FILE"`
	AuthGRPCTLSCertFile string `env:"GATEWAY_GRPC_TLS_CERT_FILE"`
	AuthGRPCTLSKeyFile  string `env:"GATEWAY_GRPC_TLS_KEY_FILE"`
	AuthGRPCServerName  string `env:"AUTH_GRPC_SERVER_NAME"`
	AuthServiceToken    string `env:"AUTH_SERVICE_TOKEN"`
}

func LoadConfig() (*Config, error) {
	_ = godotenv.Load()

	var cfg Config
	if err := env.Parse(&cfg); err != nil {
		return nil, fmt.Errorf("parse config environment variables: %w", err)
	}

	if cfg.GatewayConfigPath == "" {
		return nil, fmt.Errorf("GATEWAY_CONFIG_PATH is required and cannot be empty")
	}

	return &cfg, nil
}
