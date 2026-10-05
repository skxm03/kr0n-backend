package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
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
	DatabaseURL  string
	AuthGRPCAddr string
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

	return &Config{
		DatabaseURL:  databaseURL,
		AuthGRPCAddr: authGRPCAddr,
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
