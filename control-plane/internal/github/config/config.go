package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config encapsulates configuration for the GitHub microservice.
type Config struct {
	GRPCPort         string
	AuthGRPCAddr     string
	GitHubAPIURL     string
	HTTPTimeout      time.Duration
	CacheTTL         time.Duration
	MaxResponseBytes int64

	// TLS / mTLS settings
	TLSEnabled            bool
	TLSCertFile           string
	TLSKeyFile            string
	TLSCAFile             string
	TLSClientAuth         bool
	InsecureDevSkipVerify bool

	// Audit settings
	AuditRabbitMQURL  string
	AuditExchangeName string
}

// Load reads configuration from environment variables with production defaults.
func Load() (*Config, error) {
	cfg := &Config{
		GRPCPort:              getEnv("GITHUB_GRPC_PORT", "50052"),
		AuthGRPCAddr:          getEnv("AUTH_GRPC_ADDR", "127.0.0.1:50051"),
		GitHubAPIURL:          getEnv("GITHUB_API_URL", "https://api.github.com"),
		HTTPTimeout:           getEnvDuration("GITHUB_HTTP_TIMEOUT", 5*time.Second),
		CacheTTL:              getEnvDuration("GITHUB_CACHE_TTL", 2*time.Minute),
		MaxResponseBytes:      getEnvInt64("GITHUB_MAX_RESPONSE_BYTES", 4<<20), // 4MB
		TLSEnabled:            getEnvBool("GITHUB_TLS_ENABLED", false),
		TLSCertFile:           os.Getenv("GITHUB_TLS_CERT_FILE"),
		TLSKeyFile:            os.Getenv("GITHUB_TLS_KEY_FILE"),
		TLSCAFile:             os.Getenv("GITHUB_TLS_CA_FILE"),
		TLSClientAuth:         getEnvBool("GITHUB_TLS_CLIENT_AUTH", false),
		InsecureDevSkipVerify: getEnvBool("GITHUB_INSECURE_DEV_SKIP_VERIFY", false),
		AuditRabbitMQURL:      os.Getenv("AUDIT_RABBITMQ_URL"),
		AuditExchangeName:     getEnv("AUDIT_EXCHANGE_NAME", "audit.events"),
	}

	if cfg.TLSEnabled {
		if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
			return nil, fmt.Errorf("GITHUB_TLS_ENABLED is true but GITHUB_TLS_CERT_FILE or GITHUB_TLS_KEY_FILE is missing")
		}
	}

	return cfg, nil
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getEnvDuration(key string, defaultVal time.Duration) time.Duration {
	if val := os.Getenv(key); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			return d
		}
	}
	return defaultVal
}

func getEnvInt64(key string, defaultVal int64) int64 {
	if val := os.Getenv(key); val != "" {
		if n, err := strconv.ParseInt(val, 10, 64); err == nil {
			return n
		}
	}
	return defaultVal
}

func getEnvBool(key string, defaultVal bool) bool {
	if val := os.Getenv(key); val != "" {
		if b, err := strconv.ParseBool(val); err == nil {
			return b
		}
	}
	return defaultVal
}
