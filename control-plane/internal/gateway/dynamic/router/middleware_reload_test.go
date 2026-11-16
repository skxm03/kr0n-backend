package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"

	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/dynamic/config"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/dynamic/registry"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware/builtins"
)

func TestManager_MiddlewarePipelineAndReload(t *testing.T) {
	// 1. Service registry
	reg := registry.NewRegistry()
	_ = reg.Register("auth", func(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
		_ = mux.HandlePath("GET", "/api/v1/public", func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`public_ok`))
		})
		_ = mux.HandlePath("GET", "/api/v1/protected", func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`protected_ok`))
		})
		return nil
	})

	// 2. Middleware registry with built-ins
	mwReg := middleware.NewRegistry()
	_ = builtins.RegisterDefaults(mwReg, builtins.SharedDeps{})

	mgr := NewManager(ManagerOptions{
		Registry:           reg,
		MiddlewareRegistry: mwReg,
		Dialer: func(svc config.ServiceConfig) (*grpc.ClientConn, error) {
			return nil, nil
		},
	})
	defer mgr.Close()

	// Initial configuration with CORS, request_id, and rate_limit
	cfgV1 := &config.GatewayConfig{
		Gateway: config.ServerConfig{
			Middleware: []middleware.MiddlewareItem{
				{Name: "request_id"},
			},
		},
		MiddlewareProfiles: map[string][]middleware.MiddlewareItem{
			"public": {
				{Name: "cors"},
				{Name: "rate_limit", Config: map[string]any{"requests": 5, "window": "1m"}},
			},
			"auth_required": {
				{Name: "authentication"},
			},
		},
		Services: map[string]config.ServiceConfig{
			"auth": {
				Address: "mock:1234",
				Endpoints: []config.EndpointConfig{
					{
						Path:   "/api/v1/public",
						Method: "GET",
						Use:    []string{"public"},
					},
					{
						Path:   "/api/v1/protected",
						Method: "GET",
						Use:    []string{"auth_required"},
					},
				},
			},
		},
	}

	if err := mgr.Initialize(context.Background(), cfgV1); err != nil {
		t.Fatalf("failed to initialize manager: %v", err)
	}

	// 1. Public route: receives X-Request-ID, RateLimit headers, and 200
	req := httptest.NewRequest("GET", "/api/v1/public", nil)
	rec := httptest.NewRecorder()
	mgr.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 on public route, got %d", rec.Code)
	}
	if rec.Header().Get("X-Request-ID") == "" {
		t.Errorf("expected X-Request-ID header to be present")
	}
	if rec.Header().Get("RateLimit-Limit") != "5" {
		t.Errorf("expected RateLimit-Limit header 5, got %s", rec.Header().Get("RateLimit-Limit"))
	}

	// 2. Protected route: requires authentication, without token returns 401
	reqAuth := httptest.NewRequest("GET", "/api/v1/protected", nil)
	recAuth := httptest.NewRecorder()
	mgr.ServeHTTP(recAuth, reqAuth)

	if recAuth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 on unauthenticated call, got %d", recAuth.Code)
	}

	// 3. Hot-reload with updated rate limit and CORS configuration
	cfgV2 := &config.GatewayConfig{
		Gateway: config.ServerConfig{
			Middleware: []middleware.MiddlewareItem{
				{Name: "request_id"},
			},
		},
		MiddlewareProfiles: map[string][]middleware.MiddlewareItem{
			"public": {
				{Name: "cors", Config: map[string]any{"allow_credentials": true}},
				{Name: "rate_limit", Config: map[string]any{"requests": 50, "window": "1m"}},
			},
		},
		Services: map[string]config.ServiceConfig{
			"auth": {
				Address: "mock:1234",
				Endpoints: []config.EndpointConfig{
					{
						Path:   "/api/v1/public",
						Method: "GET",
						Use:    []string{"public"},
					},
				},
			},
		},
	}

	if err := mgr.Reload(context.Background(), cfgV2); err != nil {
		t.Fatalf("failed to reload manager: %v", err)
	}

	// Verify updated policy takes effect immediately
	recV2 := httptest.NewRecorder()
	reqV2 := httptest.NewRequest("GET", "/api/v1/public", nil)
	reqV2.Header.Set("Origin", "http://example.com")
	mgr.ServeHTTP(recV2, reqV2)

	if recV2.Code != http.StatusOK {
		t.Errorf("expected 200 on public route after reload, got %d", recV2.Code)
	}
	if recV2.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Errorf("expected Access-Control-Allow-Credentials true, got %s", recV2.Header().Get("Access-Control-Allow-Credentials"))
	}

	// 4. Invalid reload with unknown middleware: must fail safely and keep current router active
	cfgBad := &config.GatewayConfig{
		Services: map[string]config.ServiceConfig{
			"auth": {
				Address: "mock:1234",
				Endpoints: []config.EndpointConfig{
					{
						Path:   "/api/v1/public",
						Method: "GET",
						Middleware: []middleware.MiddlewareItem{
							{Name: "nonexistent_middleware"},
						},
					},
				},
			},
		},
	}

	err := mgr.Reload(context.Background(), cfgBad)
	if err == nil {
		t.Fatalf("expected reload error for unknown middleware, got nil")
	}

	// Assert previous configuration remains active
	recAfterBad := httptest.NewRecorder()
	mgr.ServeHTTP(recAfterBad, httptest.NewRequest("GET", "/api/v1/public", nil))
	if recAfterBad.Code != http.StatusOK {
		t.Errorf("expected public route to remain active after bad reload, got %d", recAfterBad.Code)
	}
}
