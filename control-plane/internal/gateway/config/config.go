package config

import (
	"fmt"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

type Config struct {
	GatewayHTTPAddr     string   `env:"GATEWAY_HTTP_ADDR"`
	AuthGRPCAddr        string   `env:"AUTH_GRPC_ADDR"`
	Env                 string   `env:"KR0N_ENV"`
	JWTPublicKeys       string   `env:"JWT_PUBLIC_KEYS"`
	JWTKeyID            string   `env:"JWT_KEY_ID"`
	JWTIssuer           string   `env:"JWT_ISSUER"`
	JWTAudience         string   `env:"JWT_AUDIENCE"`
	RedisAddr           string   `env:"REDIS_ADDR"`
	TrustedProxyCIDRs   []string `env:"TRUSTED_PROXY_CIDRS"`
	GeneralRateCapacity int      `env:"RATE_LIMIT_CAPACITY"`
	GeneralRatePerSec   float64  `env:"RATE_LIMIT_PER_SEC"`
	AuthRateCapacity    int      `env:"AUTH_RATE_LIMIT_CAPACITY"`
	AuthRatePerSec      float64  `env:"AUTH_RATE_LIMIT_PER_SEC"`
	AuthGRPCTLSEnabled  bool     `env:"AUTH_GRPC_TLS_ENABLED"`
	AuthGRPCTLSCAFile   string   `env:"AUTH_GRPC_TLS_CA_FILE"`
	AuthGRPCTLSCertFile string   `env:"GATEWAY_GRPC_TLS_CERT_FILE"`
	AuthGRPCTLSKeyFile  string   `env:"GATEWAY_GRPC_TLS_KEY_FILE"`
	AuthGRPCServerName  string   `env:"AUTH_GRPC_SERVER_NAME"`
	AuthServiceToken    string   `env:"AUTH_SERVICE_TOKEN"`
}

func LoadConfig() (*Config, error) {
	_ = godotenv.Load()

	var cfg Config
	if err := env.Parse(&cfg); err != nil {
		return nil, fmt.Errorf("parse config environment variables: %w", err)
	}

	return &cfg, nil
}
