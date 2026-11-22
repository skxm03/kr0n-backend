package config

import (
	"os"
	"testing"
	"time"
)

func TestConfigLoadDefaults(t *testing.T) {
	// Clear any overrides for predictable baseline testing
	_ = os.Unsetenv("GITHUB_GRPC_ADDR")
	_ = os.Unsetenv("GITHUB_GRPC_PORT")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error loading config: %v", err)
	}

	if cfg.GRPCPort == "" {
		t.Errorf("expected GRPCPort to have default, got empty")
	}
	if cfg.GRPCAddr == "" {
		t.Errorf("expected GRPCAddr to have default, got empty")
	}
	if cfg.HTTPTimeout <= 0 {
		t.Errorf("expected positive HTTPTimeout, got %v", cfg.HTTPTimeout)
	}
	if cfg.CacheTTL <= 0 {
		t.Errorf("expected positive CacheTTL, got %v", cfg.CacheTTL)
	}
}

func TestConfigLoadEnvOverrides(t *testing.T) {
	t.Setenv("GITHUB_GRPC_ADDR", "127.0.0.1:60052")
	t.Setenv("GITHUB_GRPC_PORT", "60052")
	t.Setenv("GITHUB_HTTP_TIMEOUT", "10s")
	t.Setenv("GITHUB_MAX_RESPONSE_BYTES", "8388608")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error loading config: %v", err)
	}

	if cfg.GRPCAddr != "127.0.0.1:60052" {
		t.Errorf("expected GRPCAddr 127.0.0.1:60052, got %s", cfg.GRPCAddr)
	}
	if cfg.GRPCPort != "60052" {
		t.Errorf("expected GRPCPort 60052, got %s", cfg.GRPCPort)
	}
	if cfg.HTTPTimeout != 10*time.Second {
		t.Errorf("expected HTTPTimeout 10s, got %v", cfg.HTTPTimeout)
	}
	if cfg.MaxResponseBytes != 8388608 {
		t.Errorf("expected MaxResponseBytes 8388608, got %d", cfg.MaxResponseBytes)
	}
}
