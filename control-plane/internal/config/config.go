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

// Config represents the application configuration.
type Config struct {
	DatabaseURL string
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

	return &Config{
		DatabaseURL: databaseURL,
	}, nil
}
