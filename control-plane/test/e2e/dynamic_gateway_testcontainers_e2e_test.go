package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/jwtkeys"
)

func TestE2E_DynamicGateway_Testcontainers_FullFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testcontainers E2E test in short mode")
	}

	// 1. Verify Docker daemon is reachable
	cmd := exec.Command("docker", "info")
	if err := cmd.Run(); err != nil {
		t.Skipf("skipping E2E test, docker is not reachable: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	tmpDir := t.TempDir()

	upstreamBuildDir := filepath.Join(tmpDir, "upstream_build")
	require.NoError(t, os.MkdirAll(upstreamBuildDir, 0755))
	upstreamBinPath := filepath.Join(upstreamBuildDir, "upstream")

	gatewayBuildDir := filepath.Join(tmpDir, "gateway_build")
	require.NoError(t, os.MkdirAll(gatewayBuildDir, 0755))
	gatewayBinPath := filepath.Join(gatewayBuildDir, "kr0n-gateway")

	// 2. Pre-compile upstream and gateway Linux binaries for fast, reproducible container startup
	t.Log("Building upstream Linux binary...")
	buildUpstream := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", upstreamBinPath, "../testupstream")
	buildUpstream.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux")
	out, err := buildUpstream.CombinedOutput()
	require.NoError(t, err, "failed to compile upstream: %s", string(out))

	t.Log("Building gateway Linux binary...")
	buildGateway := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", gatewayBinPath, "../../cmd/gateway")
	buildGateway.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux")
	out, err = buildGateway.CombinedOutput()
	require.NoError(t, err, "failed to compile gateway: %s", string(out))

	t.Log("Generating mTLS test certificates...")
	certsDir := filepath.Join(tmpDir, "certs")
	genCerts := exec.CommandContext(ctx, "../../../scripts/gen-certs.sh", certsDir)
	out, err = genCerts.CombinedOutput()
	require.NoError(t, err, "failed to generate mTLS certs: %s", string(out))

	// Copy certs into isolated build directories
	require.NoError(t, os.MkdirAll(filepath.Join(upstreamBuildDir, "tls"), 0755))
	require.NoError(t, copyTestFile(filepath.Join(certsDir, "auth", "server.crt"), filepath.Join(upstreamBuildDir, "tls", "server.crt")))
	require.NoError(t, copyTestFile(filepath.Join(certsDir, "auth", "server.key"), filepath.Join(upstreamBuildDir, "tls", "server.key")))

	require.NoError(t, os.MkdirAll(filepath.Join(gatewayBuildDir, "tls"), 0755))
	require.NoError(t, copyTestFile(filepath.Join(certsDir, "ca", "ca.crt"), filepath.Join(gatewayBuildDir, "tls", "ca.crt")))
	require.NoError(t, copyTestFile(filepath.Join(certsDir, "gateway", "client.crt"), filepath.Join(gatewayBuildDir, "tls", "client.crt")))
	require.NoError(t, copyTestFile(filepath.Join(certsDir, "gateway", "client.key"), filepath.Join(gatewayBuildDir, "tls", "client.key")))

	// 3. Create test gateway.yaml declarative configuration
	gatewayYAML := `
gateway:
  http_addr: ":8080"
  read_timeout: 10s
  write_timeout: 10s
  idle_timeout: 30s
  max_body_bytes: 4194304

  middleware:
    - request_id
    - recovery
    - access_log

middleware_profiles:
  public_api:
    - cors
    - request_validation
    - rate_limit:
        requests: 100
        window: 1m

  authenticated_api:
    - cors
    - authentication:
        allow_api_tokens: true
    - rate_limit:
        requests: 200
        window: 1m

services:
  auth:
    address: "${AUTH_GRPC_ADDR:-mock-upstream:50051}"
    enabled: true
    timeout: 5s
    tls:
      ca_file: "/etc/kr0n/tls/ca.crt"
      cert_file: "/etc/kr0n/tls/client.crt"
      key_file: "/etc/kr0n/tls/client.key"
      server_name: "auth.internal"

    middleware:
      - cors

    groups:
      user_profile:
        match:
          - path: "/api/v1/me"
            type: exact
            methods: [GET]
        use:
          - authenticated_api

    endpoints:
      - path: "/api/v1/me"
        method: "GET"
        use:
          - authenticated_api
`
	gatewayYAMLPath := filepath.Join(gatewayBuildDir, "gateway.yaml")
	require.NoError(t, os.WriteFile(gatewayYAMLPath, []byte(strings.TrimSpace(gatewayYAML)), 0644))

	// 4. Create Docker network for container-to-container communication
	dockerNet, err := network.New(ctx, network.WithDriver("bridge"), network.WithCheckDuplicate())
	require.NoError(t, err, "failed to create docker network")
	t.Cleanup(func() {
		_ = dockerNet.Remove(context.Background())
	})

	// 5. Spin up Redis Testcontainer for distributed rate limiting
	t.Log("Spinning up Redis container...")
	redisCtr, err := tcredis.Run(
		ctx,
		"redis:7-alpine",
		network.WithNetwork([]string{"redis"}, dockerNet),
	)
	require.NoError(t, err, "failed to start redis container")
	t.Cleanup(func() {
		_ = testcontainers.TerminateContainer(redisCtr)
	})

	// 6. Write Dockerfile for upstream API and spin up upstream Testcontainer with TLS
	upstreamDockerfile := `FROM alpine:3.21
COPY upstream /bin/upstream
COPY tls/server.crt /etc/kr0n/tls/server.crt
COPY tls/server.key /etc/kr0n/tls/server.key
ENV TLS_CERT_FILE=/etc/kr0n/tls/server.crt
ENV TLS_KEY_FILE=/etc/kr0n/tls/server.key
EXPOSE 50051
ENTRYPOINT ["/bin/upstream"]
`
	require.NoError(t, os.WriteFile(filepath.Join(upstreamBuildDir, "Dockerfile"), []byte(upstreamDockerfile), 0644))

	t.Log("Spinning up Upstream API container with TLS...")
	upstreamCtr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{
				Context:    upstreamBuildDir,
				Dockerfile: "Dockerfile",
			},
			Networks: []string{dockerNet.Name},
			NetworkAliases: map[string][]string{
				dockerNet.Name: {"mock-upstream"},
			},
			ExposedPorts: []string{"50051/tcp"},
			WaitingFor:   wait.ForListeningPort("50051/tcp").WithStartupTimeout(30 * time.Second),
		},
		Started: true,
	})
	require.NoError(t, err, "failed to start upstream container")
	t.Cleanup(func() {
		_ = testcontainers.TerminateContainer(upstreamCtr)
	})

	// 7. Write Dockerfile for Gateway and spin up Gateway Testcontainer with TLS client certs
	gatewayDockerfile := `FROM alpine:3.21
COPY kr0n-gateway /bin/kr0n-gateway
COPY gateway.yaml /etc/kr0n/gateway.yaml
COPY tls/ca.crt /etc/kr0n/tls/ca.crt
COPY tls/client.crt /etc/kr0n/tls/client.crt
COPY tls/client.key /etc/kr0n/tls/client.key
EXPOSE 8080
ENTRYPOINT ["/bin/kr0n-gateway"]
`
	require.NoError(t, os.WriteFile(filepath.Join(gatewayBuildDir, "Dockerfile"), []byte(gatewayDockerfile), 0644))

	t.Log("Spinning up Gateway container with TLS...")
	gatewayCtr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{
				Context:    gatewayBuildDir,
				Dockerfile: "Dockerfile",
			},
			Networks: []string{dockerNet.Name},
			NetworkAliases: map[string][]string{
				dockerNet.Name: {"kr0n-gateway"},
			},
			Env: map[string]string{
				"KR0N_ENV":                   "dev",
				"GATEWAY_HTTP_ADDR":          ":8080",
				"AUTH_GRPC_ADDR":             "mock-upstream:50051",
				"REDIS_ADDR":                 "redis:6379",
				"GATEWAY_CONFIG_PATH":        "/etc/kr0n/gateway.yaml",
				"AUTH_GRPC_TLS_CA_FILE":      "/etc/kr0n/tls/ca.crt",
				"GATEWAY_GRPC_TLS_CERT_FILE": "/etc/kr0n/tls/client.crt",
				"GATEWAY_GRPC_TLS_KEY_FILE":  "/etc/kr0n/tls/client.key",
				"AUTH_GRPC_SERVER_NAME":      "auth.internal",
			},
			ExposedPorts: []string{"8080/tcp"},
			WaitingFor:   wait.ForHTTP("/healthz").WithPort("8080/tcp").WithStartupTimeout(30 * time.Second),
		},
		Started: true,
	})
	require.NoError(t, err, "failed to start gateway container")
	t.Cleanup(func() {
		_ = testcontainers.TerminateContainer(gatewayCtr)
	})

	// 8. Resolve Gateway public mapped endpoint from host
	gwHost, err := gatewayCtr.Host(ctx)
	require.NoError(t, err)
	gwPort, err := gatewayCtr.MappedPort(ctx, "8080/tcp")
	require.NoError(t, err)
	baseURL := fmt.Sprintf("http://%s:%s", gwHost, gwPort.Port())
	t.Logf("Gateway container running and exposed at %s", baseURL)

	client := &http.Client{Timeout: 5 * time.Second}

	// 9. Execute Real E2E Flow Checks

	// Step A: Healthz endpoint (unprotected router endpoint)
	t.Run("Healthz returns 200 OK", func(t *testing.T) {
		resp, err := client.Get(baseURL + "/healthz")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		var body map[string]string
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.Equal(t, "ok", body["status"])
	})

	// Step B: Unauthenticated request to protected endpoint (middleware must block)
	t.Run("Unauthenticated request to protected endpoint is rejected with 401", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/v1/me", nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		raw, _ := io.ReadAll(resp.Body)
		assert.Contains(t, strings.ToLower(string(raw)), "unauthorized")
	})

	// Step C: Request with malformed Bearer token is rejected with 401
	t.Run("Invalid bearer token is rejected with 401", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/v1/me", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer invalid.garbage.token")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	// Step D: Valid Ed25519 JWT Bearer token succeeds through Gateway -> Upstream -> Response
	t.Run("Valid Ed25519 Bearer token authenticates and proxies to upstream container", func(t *testing.T) {
		jwtSigner, err := jwtkeys.NewSigner(
			jwtkeys.DevPrivateKey(),
			"k1",
			"kr0n-auth",
			"kr0n-api",
			15*time.Minute,
		)
		require.NoError(t, err)

		userID := uuid.New()
		sessionID := uuid.New()
		tokenStr, _, err := jwtSigner.Sign(userID, sessionID, time.Now())
		require.NoError(t, err)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/v1/me", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+tokenStr)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Verify middleware headers
		reqID := resp.Header.Get("X-Request-Id")
		assert.NotEmpty(t, reqID, "request_id middleware should attach X-Request-Id header")

		// Verify body returned from upstream container
		var res struct {
			Id          string `json:"id"`
			Email       string `json:"email"`
			DisplayName string `json:"display_name"`
			Status      string `json:"status"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&res))
		assert.Equal(t, "e2e-user-001", res.Id)
		assert.Equal(t, "admin@kr0n.dev", res.Email)
		assert.Equal(t, "E2E Administrator", res.DisplayName)
		assert.Equal(t, "active", res.Status)
	})

	// Step E: Valid PAT API Token succeeds through Gateway -> Upstream -> Response
	t.Run("Valid PAT API token authenticates via upstream ValidateAPIToken", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/v1/me", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer kr0n_pat_valid_test_token")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		var res map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&res))
		assert.Equal(t, "e2e-user-001", res["id"])
	})

	// Step F: CORS preflight request triggers CORS middleware
	t.Run("CORS preflight request returns Access-Control headers", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodOptions, baseURL+"/api/v1/me", nil)
		require.NoError(t, err)
		req.Header.Set("Origin", "http://localhost:3000")
		req.Header.Set("Access-Control-Request-Method", "GET")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent, "CORS status %d", resp.StatusCode)
		assert.NotEmpty(t, resp.Header.Get("Access-Control-Allow-Origin"))
	})

	// Step G: Unregistered / Non-whitelisted route returns 404
	t.Run("Unregistered endpoint is blocked by router allowlist with 404", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/v1/not-in-yaml", nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

func copyTestFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}
