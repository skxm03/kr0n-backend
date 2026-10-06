package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	// ErrMissingDatabaseURL indicates the DATABASE_URL environment variable is not set.
	ErrMissingDatabaseURL = errors.New("missing required environment variable: DATABASE_URL")

	// ErrEmptyDatabaseURL indicates the DATABASE_URL environment variable is empty.
	ErrEmptyDatabaseURL = errors.New("DATABASE_URL cannot be empty")

	// ErrInvalidDatabaseURL indicates the DATABASE_URL environment variable is malformed.
	ErrInvalidDatabaseURL = errors.New("DATABASE_URL is invalid")
)

// Config represents the application configuration for database-backed services.
type Config struct {
	DatabaseURL          string
	AuthGRPCAddr         string
	JWTSigningKey        string
	JWTIssuer            string
	AccessTokenLifetime  time.Duration
	RefreshTokenLifetime time.Duration
}

// GatewayConfig represents configuration for the API Gateway service.
type GatewayConfig struct {
	GatewayHTTPAddr string
	AuthGRPCAddr    string
}

// Load loads and validates configuration from the process environment.
func Load() (*Config, error) {
	return LoadFrom(os.LookupEnv)
}

// LoadFrom loads and validates configuration using the provided environment lookup function.
func LoadFrom(lookup func(string) (string, bool)) (*Config, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}

	rawURL, ok := lookup("DATABASE_URL")
	if !ok {
		return nil, ErrMissingDatabaseURL
	}

	databaseURL := strings.TrimSpace(rawURL)
	if databaseURL == "" {
		return nil, ErrEmptyDatabaseURL
	}

	u, err := url.Parse(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidDatabaseURL, err)
	}

	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return nil, fmt.Errorf("%w: scheme must be postgres:// or postgresql://", ErrInvalidDatabaseURL)
	}

	if u.Host == "" {
		return nil, fmt.Errorf("%w: missing host", ErrInvalidDatabaseURL)
	}

	authGRPCAddr := ":50051"
	if raw, ok := lookup("AUTH_GRPC_ADDR"); ok && strings.TrimSpace(raw) != "" {
		authGRPCAddr = strings.TrimSpace(raw)
	}

	jwtSigningKey := "kr0n_dev_insecure_jwt_signing_key_32_bytes_min!"
	if raw, ok := lookup("JWT_SIGNING_KEY"); ok && strings.TrimSpace(raw) != "" {
		jwtSigningKey = strings.TrimSpace(raw)
	}
	if len(jwtSigningKey) < 32 {
		return nil, errors.New("JWT_SIGNING_KEY must be at least 32 bytes")
	}

	jwtIssuer := "kr0n-auth"
	if raw, ok := lookup("JWT_ISSUER"); ok && strings.TrimSpace(raw) != "" {
		jwtIssuer = strings.TrimSpace(raw)
	}

	accessTokenLifetime := 15 * time.Minute
	if raw, ok := lookup("ACCESS_TOKEN_LIFETIME"); ok && strings.TrimSpace(raw) != "" {
		d, err := time.ParseDuration(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("invalid ACCESS_TOKEN_LIFETIME: %w", err)
		}
		if d <= 0 {
			return nil, errors.New("ACCESS_TOKEN_LIFETIME must be positive")
		}
		accessTokenLifetime = d
	}

	refreshTokenLifetime := 30 * 24 * time.Hour
	if raw, ok := lookup("REFRESH_TOKEN_LIFETIME"); ok && strings.TrimSpace(raw) != "" {
		d, err := time.ParseDuration(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("invalid REFRESH_TOKEN_LIFETIME: %w", err)
		}
		if d <= 0 {
			return nil, errors.New("REFRESH_TOKEN_LIFETIME must be positive")
		}
		refreshTokenLifetime = d
	}

	return &Config{
		DatabaseURL:          databaseURL,
		AuthGRPCAddr:         authGRPCAddr,
		JWTSigningKey:        jwtSigningKey,
		JWTIssuer:            jwtIssuer,
		AccessTokenLifetime:  accessTokenLifetime,
		RefreshTokenLifetime: refreshTokenLifetime,
	}, nil
}

// LoadGateway loads configuration for the API Gateway service.
func LoadGateway() (*GatewayConfig, error) {
	return LoadGatewayFrom(os.LookupEnv)
}

// LoadGatewayFrom loads configuration for the API Gateway service using lookup.
func LoadGatewayFrom(lookup func(string) (string, bool)) (*GatewayConfig, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}

	gatewayHTTPAddr := ":8080"
	if raw, ok := lookup("GATEWAY_HTTP_ADDR"); ok && strings.TrimSpace(raw) != "" {
		gatewayHTTPAddr = strings.TrimSpace(raw)
	}

	authGRPCAddr := "localhost:50051"
	if raw, ok := lookup("AUTH_GRPC_ADDR"); ok && strings.TrimSpace(raw) != "" {
		authGRPCAddr = strings.TrimSpace(raw)
	}

	return &GatewayConfig{
		GatewayHTTPAddr: gatewayHTTPAddr,
		AuthGRPCAddr:    authGRPCAddr,
	}, nil
}
