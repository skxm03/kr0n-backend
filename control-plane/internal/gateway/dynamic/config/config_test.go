package config

import (
	"os"
	"testing"
	"time"
)

func TestLoadConfig_ValidYAML(t *testing.T) {
	yamlData := `
gateway:
  http_addr: ":9090"
  read_timeout: 5s
  write_timeout: 10s
  idle_timeout: 30s
  max_body_bytes: 2097152

services:
  auth:
    address: "localhost:50051"
    timeout: 3s
    endpoints:
      - path: "/api/v1/auth/login"
        method: "POST"
        timeout: 2s
      - path: "/api/v1/me"
        method: "GET"
`
	cfg, err := LoadConfig([]byte(yamlData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Gateway.HTTPAddr != ":9090" {
		t.Errorf("expected HTTPAddr :9090, got %s", cfg.Gateway.HTTPAddr)
	}
	if cfg.Gateway.ReadTimeout != 5*time.Second {
		t.Errorf("expected ReadTimeout 5s, got %v", cfg.Gateway.ReadTimeout)
	}
	if cfg.Gateway.MaxBodyBytes != 2097152 {
		t.Errorf("expected MaxBodyBytes 2097152, got %d", cfg.Gateway.MaxBodyBytes)
	}

	auth, ok := cfg.Services["auth"]
	if !ok {
		t.Fatalf("expected service 'auth' to exist")
	}
	if !auth.IsEnabled() {
		t.Errorf("expected auth service to be enabled by default")
	}
	if auth.Address != "localhost:50051" {
		t.Errorf("expected address localhost:50051, got %s", auth.Address)
	}
	if len(auth.Endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(auth.Endpoints))
	}
	if auth.Endpoints[0].Method != "POST" || auth.Endpoints[0].Path != "/api/v1/auth/login" {
		t.Errorf("unexpected endpoint 0: %+v", auth.Endpoints[0])
	}
	if auth.Endpoints[0].Timeout != 2*time.Second {
		t.Errorf("expected endpoint timeout 2s, got %v", auth.Endpoints[0].Timeout)
	}
}

func TestLoadConfig_EnvExpansion(t *testing.T) {
	_ = os.Setenv("TEST_GATEWAY_PORT", "8888")
	_ = os.Setenv("TEST_AUTH_HOST", "auth.internal")
	defer os.Unsetenv("TEST_GATEWAY_PORT")
	defer os.Unsetenv("TEST_AUTH_HOST")

	yamlData := `
gateway:
  http_addr: ":${TEST_GATEWAY_PORT:-8080}"

services:
  auth:
    address: "${TEST_AUTH_HOST}:${TEST_AUTH_PORT:-50051}"
    endpoints:
      - path: "/health"
        method: "GET"
`
	cfg, err := LoadConfig([]byte(yamlData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Gateway.HTTPAddr != ":8888" {
		t.Errorf("expected :8888, got %s", cfg.Gateway.HTTPAddr)
	}
	auth := cfg.Services["auth"]
	if auth.Address != "auth.internal:50051" {
		t.Errorf("expected auth.internal:50051, got %s", auth.Address)
	}
}

func TestValidate_DuplicateRoutesAcrossServices(t *testing.T) {
	yamlData := `
services:
  service_a:
    address: "localhost:50051"
    endpoints:
      - path: "/api/test"
        method: "POST"
  service_b:
    address: "localhost:50052"
    endpoints:
      - path: "/api/test"
        method: "POST"
`
	_, err := LoadConfig([]byte(yamlData))
	if err == nil {
		t.Fatalf("expected validation error for duplicate route, got nil")
	}
}

func TestValidate_InvalidHTTPMethod(t *testing.T) {
	yamlData := `
services:
  auth:
    address: "localhost:50051"
    endpoints:
      - path: "/api/test"
        method: "INVALID_METHOD"
`
	_, err := LoadConfig([]byte(yamlData))
	if err == nil {
		t.Fatalf("expected validation error for invalid HTTP method, got nil")
	}
}

func TestValidate_InvalidPath(t *testing.T) {
	yamlData := `
services:
  auth:
    address: "localhost:50051"
    endpoints:
      - path: "no-leading-slash"
        method: "GET"
`
	_, err := LoadConfig([]byte(yamlData))
	if err == nil {
		t.Fatalf("expected validation error for missing leading slash, got nil")
	}
}

func TestValidate_EmptyServiceAddress(t *testing.T) {
	yamlData := `
services:
  auth:
    address: ""
    endpoints:
      - path: "/test"
        method: "GET"
`
	_, err := LoadConfig([]byte(yamlData))
	if err == nil {
		t.Fatalf("expected validation error for empty address, got nil")
	}
}

func TestValidate_DisabledServiceRequiresAddress(t *testing.T) {
	yamlData := `
services:
  disabled_service:
    address: ""
    enabled: false
    endpoints:
      - path: "/disabled"
        method: "GET"
`
	if _, err := LoadConfig([]byte(yamlData)); err == nil {
		t.Fatalf("expected validation error for disabled service without address in YAML or .env, got nil")
	}
}

func TestLoadConfig_DynamicEnvServiceAddressFallback(t *testing.T) {
	_ = os.Setenv("BILLING_GRPC_ADDR", "billing.internal:50052")
	defer os.Unsetenv("BILLING_GRPC_ADDR")

	yamlData := `
services:
  billing:
    enabled: false
    endpoints:
      - path: "/api/v1/billing"
        method: "GET"
`
	cfg, err := LoadConfig([]byte(yamlData))
	if err != nil {
		t.Fatalf("unexpected error when address is provided via env: %v", err)
	}
	if got := cfg.Services["billing"].Address; got != "billing.internal:50052" {
		t.Fatalf("expected billing address from BILLING_GRPC_ADDR, got %q", got)
	}
}
