package router

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/dynamic/config"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/dynamic/registry"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware/builtins"
)

func TestSnapshot_LifecycleAndConns(t *testing.T) {
	snap := NewSnapshot(http.NotFoundHandler(), nil)

	if !snap.Acquire() {
		t.Fatalf("expected Acquire to succeed on fresh snapshot")
	}
	if snap.InFlight() != 1 {
		t.Errorf("expected 1 in-flight, got %d", snap.InFlight())
	}

	snap.Retire()
	if !snap.IsRetired() {
		t.Errorf("expected snapshot to be retired")
	}

	// Once retired, new Acquire must fail
	if snap.Acquire() {
		t.Errorf("expected Acquire to fail on retired snapshot")
	}

	// Release in-flight request
	doneCh := make(chan struct{})
	go func() {
		snap.WaitAndClose(1 * time.Second)
		close(doneCh)
	}()

	snap.Release()

	select {
	case <-doneCh:
		// Successfully notified and closed!
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("WaitAndClose did not unblock after inFlight reached 0")
	}
}

func TestSnapshot_EndpointAllowlisting(t *testing.T) {
	reg := registry.NewRegistry()

	// Register a mock service registrar that adds two paths to ServeMux
	_ = reg.Register("test_svc", func(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
		_ = mux.HandlePath("POST", "/api/v1/allowed", func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"allowed"}`))
		})
		_ = mux.HandlePath("POST", "/api/v1/forbidden", func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"forbidden"}`))
		})
		return nil
	})

	// YAML only enables /api/v1/allowed
	cfg := &config.GatewayConfig{
		Services: map[string]config.ServiceConfig{
			"test_svc": {
				Address: "mock:1234",
				Endpoints: []config.EndpointConfig{
					{
						Path:   "/api/v1/allowed",
						Method: "POST",
					},
				},
			},
		},
	}

	mockDialer := func(svc config.ServiceConfig) (*grpc.ClientConn, error) {
		return nil, nil // return nil conn for unit test
	}

	snap, err := BuildSnapshot(context.Background(), cfg, SnapshotOptions{
		Registry: reg,
		Dialer:   mockDialer,
	})
	if err != nil {
		t.Fatalf("unexpected error building snapshot: %v", err)
	}

	// 1. Request to allowed endpoint must return 200
	req := httptest.NewRequest(http.MethodPost, "/api/v1/allowed", nil)
	rec := httptest.NewRecorder()
	snap.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for allowed endpoint, got %d", rec.Code)
	}

	// 2. Request to unlisted endpoint must return 404 (rejected at Chi allowlist layer)
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/forbidden", nil)
	rec2 := httptest.NewRecorder()
	snap.router.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unlisted endpoint, got %d", rec2.Code)
	}

	// 3. Health check endpoints must be independent and reachable
	reqHealth := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	recHealth := httptest.NewRecorder()
	snap.router.ServeHTTP(recHealth, reqHealth)
	if recHealth.Code != http.StatusOK {
		t.Errorf("expected 200 for /healthz, got %d", recHealth.Code)
	}
}

func TestManager_HotReloadAndZeroDowntime(t *testing.T) {
	reg := registry.NewRegistry()
	_ = reg.Register("auth", func(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
		_ = mux.HandlePath("GET", "/api/v1/v1_endpoint", func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`v1`))
		})
		_ = mux.HandlePath("GET", "/api/v1/v2_endpoint", func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`v2`))
		})
		return nil
	})

	mockDialer := func(svc config.ServiceConfig) (*grpc.ClientConn, error) {
		return nil, nil
	}

	mgr := NewManager(ManagerOptions{
		Registry: reg,
		Dialer:   mockDialer,
	})
	defer mgr.Close()

	// Initial configuration with only v1_endpoint
	cfgV1 := &config.GatewayConfig{
		Services: map[string]config.ServiceConfig{
			"auth": {
				Address: "mock:1234",
				Endpoints: []config.EndpointConfig{
					{Path: "/api/v1/v1_endpoint", Method: "GET"},
				},
			},
		},
	}

	if err := mgr.Initialize(context.Background(), cfgV1); err != nil {
		t.Fatalf("failed to initialize manager: %v", err)
	}

	// Verify v1 works, v2 is 404
	rec := httptest.NewRecorder()
	mgr.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/v1_endpoint", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "v1" {
		t.Errorf("expected v1 200, got %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	mgr.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/v2_endpoint", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected v2 404 initially, got %d", rec.Code)
	}

	// Hot reload with both v1 and v2 endpoints
	cfgV2 := &config.GatewayConfig{
		Services: map[string]config.ServiceConfig{
			"auth": {
				Address: "mock:1234",
				Endpoints: []config.EndpointConfig{
					{Path: "/api/v1/v1_endpoint", Method: "GET"},
					{Path: "/api/v1/v2_endpoint", Method: "GET"},
				},
			},
		},
	}

	if err := mgr.Reload(context.Background(), cfgV2); err != nil {
		t.Fatalf("failed to reload manager: %v", err)
	}

	// Now both v1 and v2 must be 200
	rec = httptest.NewRecorder()
	mgr.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/v2_endpoint", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "v2" {
		t.Errorf("expected v2 200 after reload, got %d %s", rec.Code, rec.Body.String())
	}

	// Invalid reload: unknown service must fail cleanly and preserve active routes
	cfgInvalid := &config.GatewayConfig{
		Services: map[string]config.ServiceConfig{
			"nonexistent_svc": {
				Address: "mock:1234",
				Endpoints: []config.EndpointConfig{
					{Path: "/bad", Method: "GET"},
				},
			},
		},
	}

	err := mgr.Reload(context.Background(), cfgInvalid)
	if err == nil {
		t.Fatalf("expected reload error for unregistered service, got nil")
	}

	// Verify v1 and v2 still work untouched!
	rec = httptest.NewRecorder()
	mgr.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/v1_endpoint", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("expected v1 to remain active after failed reload, got %d", rec.Code)
	}
}

func TestManager_ConcurrentRequestsDuringReload(t *testing.T) {
	reg := registry.NewRegistry()
	_ = reg.Register("auth", func(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
		_ = mux.HandlePath("GET", "/api/v1/slow", func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
			time.Sleep(20 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		})
		return nil
	})

	mgr := NewManager(ManagerOptions{
		Registry: reg,
		Dialer: func(svc config.ServiceConfig) (*grpc.ClientConn, error) {
			return nil, nil
		},
	})
	defer mgr.Close()

	cfg := &config.GatewayConfig{
		Services: map[string]config.ServiceConfig{
			"auth": {
				Address: "mock:1234",
				Endpoints: []config.EndpointConfig{
					{Path: "/api/v1/slow", Method: "GET"},
				},
			},
		},
	}

	_ = mgr.Initialize(context.Background(), cfg)

	var wg sync.WaitGroup
	errCh := make(chan error, 50)

	// Fire 30 concurrent slow requests
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			mgr.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/slow", nil))
			if rec.Code != http.StatusOK {
				errCh <- fmt.Errorf("unexpected status: %d", rec.Code)
			}
		}()
	}

	// Concurrently trigger reloads
	for j := 0; j < 3; j++ {
		time.Sleep(5 * time.Millisecond)
		_ = mgr.Reload(context.Background(), cfg)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("unexpected error code during concurrent reload: %v", err)
	}
}

func TestBuildSnapshot_AutoMount_DefaultEndpoints(t *testing.T) {
	// Service has NO endpoints explicitly declared in YAML, but DefaultProfile is set.
	cfg := &config.GatewayConfig{
		Gateway: config.ServerConfig{
			HTTPAddr: ":8080",
		},
		MiddlewareProfiles: map[string][]middleware.MiddlewareItem{
			"public_api": {
				{Name: "custom_header", Config: map[string]any{"header": "X-Profile", "value": "public"}},
			},
			"authenticated_api": {
				{Name: "custom_header", Config: map[string]any{"header": "X-Profile", "value": "auth"}},
			},
		},
		Services: map[string]config.ServiceConfig{
			"auth": {
				Address:        "localhost:50051",
				DefaultProfile: "authenticated_api",
				Groups: map[string]config.GroupConfig{
					"public_routes": {
						Match: []config.MatchRule{
							{Path: "/api/v1/auth/*", Type: "prefix", Methods: []string{"POST"}},
						},
						Use: []string{"public_api"},
					},
				},
				// Endpoints intentionally omitted to trigger AutoMount from Registry
			},
		},
	}

	reg := registry.DefaultRegistry()
	mwReg := middleware.NewRegistry()
	_ = mwReg.Register("custom_header", func(c map[string]any) (middleware.Middleware, error) {
		h := c["header"].(string)
		v := c["value"].(string)
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(h, v)
				next.ServeHTTP(w, r)
			})
		}, nil
	})

	snap, err := BuildSnapshot(context.Background(), cfg, SnapshotOptions{
		Registry:           reg,
		MiddlewareRegistry: mwReg,
		Dialer: func(svc config.ServiceConfig) (*grpc.ClientConn, error) {
			return grpc.NewClient("passthrough:///bufnet", grpc.WithTransportCredentials(insecure.NewCredentials()))
		},
	})
	if err != nil {
		t.Fatalf("failed to build snapshot: %v", err)
	}
	defer func() {
		snap.Retire()
		snap.WaitAndClose(5 * time.Second)
	}()

	// 1. Group-matched route (/api/v1/auth/login) should auto-mount with public_api profile
	recLogin := httptest.NewRecorder()
	snap.Router().ServeHTTP(recLogin, httptest.NewRequest("POST", "/api/v1/auth/login", nil))
	if got := recLogin.Header().Get("X-Profile"); got != "public" {
		t.Errorf("POST /api/v1/auth/login expected X-Profile 'public', got %q", got)
	}

	// 2. Non-group-matched route (/api/v1/me) should auto-mount with default_profile (authenticated_api)
	recMe := httptest.NewRecorder()
	snap.Router().ServeHTTP(recMe, httptest.NewRequest("GET", "/api/v1/me", nil))
	if got := recMe.Header().Get("X-Profile"); got != "auth" {
		t.Errorf("GET /api/v1/me expected X-Profile 'auth', got %q", got)
	}

	// 3. Unregistered route should return 404
	recNotFound := httptest.NewRecorder()
	snap.Router().ServeHTTP(recNotFound, httptest.NewRequest("GET", "/api/v1/not-a-real-endpoint", nil))
	if recNotFound.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unregistered endpoint, got %d", recNotFound.Code)
	}

	// 4. GitHub callback with installation_id redirect test
	t.Setenv("FRONTEND_URL", "http://localhost:3000")
	recInstall := httptest.NewRecorder()
	snap.Router().ServeHTTP(recInstall, httptest.NewRequest("GET", "/api/v1/auth/github/callback?installation_id=123456&setup_action=install&state=teststate", nil))
	if recInstall.Code != http.StatusFound {
		t.Errorf("expected 302 for GitHub installation callback, got %d", recInstall.Code)
	}
	expectedLoc := "http://localhost:3000/github/callback?installation_id=123456&setup_action=install&state=teststate"
	if loc := recInstall.Header().Get("Location"); loc != expectedLoc {
		t.Errorf("expected Location %q, got %q", expectedLoc, loc)
	}

	// 5. Root /github/callback endpoint redirect
	recRoot := httptest.NewRecorder()
	snap.Router().ServeHTTP(recRoot, httptest.NewRequest("GET", "/github/callback?installation_id=999", nil))
	if recRoot.Code != http.StatusFound {
		t.Errorf("expected 302 for /github/callback, got %d", recRoot.Code)
	}
	if loc := recRoot.Header().Get("Location"); loc != "http://localhost:3000/github/callback?installation_id=999" {
		t.Errorf("expected Location with installation_id=999, got %q", loc)
	}
}

func TestBuildSnapshot_DeclarativeRedirects(t *testing.T) {
	t.Setenv("FRONTEND_URL", "https://kr0n.dev")

	cfg := &config.GatewayConfig{
		Gateway: config.ServerConfig{
			Redirects: []config.RedirectConfig{
				{Path: "/app/callback", Target: "/app/callback"},
				{Path: "/custom-login", Target: "/login"},
			},
		},
		Services: map[string]config.ServiceConfig{},
	}

	snap, err := BuildSnapshot(context.Background(), cfg, SnapshotOptions{
		Registry:           registry.NewRegistry(),
		MiddlewareRegistry: middleware.NewRegistry(),
		Dialer: func(svc config.ServiceConfig) (*grpc.ClientConn, error) {
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("failed to build snapshot: %v", err)
	}
	defer func() {
		snap.Retire()
		snap.WaitAndClose(time.Second)
	}()

	// 1. First declarative redirect with query parameters
	rec1 := httptest.NewRecorder()
	snap.Router().ServeHTTP(rec1, httptest.NewRequest("GET", "/app/callback?org=acme&env=prod", nil))
	if rec1.Code != http.StatusFound {
		t.Fatalf("expected 302 Found, got %d", rec1.Code)
	}
	if loc := rec1.Header().Get("Location"); loc != "https://kr0n.dev/app/callback?org=acme&env=prod" {
		t.Fatalf("unexpected Location: %q", loc)
	}

	// 2. Second declarative redirect
	rec2 := httptest.NewRecorder()
	snap.Router().ServeHTTP(rec2, httptest.NewRequest("GET", "/custom-login", nil))
	if rec2.Code != http.StatusFound {
		t.Fatalf("expected 302 Found, got %d", rec2.Code)
	}
	if loc := rec2.Header().Get("Location"); loc != "https://kr0n.dev/login" {
		t.Fatalf("unexpected Location: %q", loc)
	}
}

func TestBuildSnapshot_ValidateWithCatalog_RejectsMisconfiguredRoute(t *testing.T) {
	// Group match has a misspelled route that does not exist in auth.proto
	cfg := &config.GatewayConfig{
		Gateway: config.ServerConfig{
			HTTPAddr: ":8080",
		},
		MiddlewareProfiles: map[string][]middleware.MiddlewareItem{
			"public_api": {},
		},
		Services: map[string]config.ServiceConfig{
			"auth": {
				Address: "localhost:50051",
				Groups: map[string]config.GroupConfig{
					"misspelled_group": {
						Match: []config.MatchRule{
							{Path: "/api/v1/auth/spelled_wrong", Type: "exact", Methods: []string{"POST"}},
						},
						Use: []string{"public_api"},
					},
				},
			},
		},
	}

	_, err := BuildSnapshot(context.Background(), cfg, SnapshotOptions{
		Registry: registry.DefaultRegistry(),
		Dialer: func(svc config.ServiceConfig) (*grpc.ClientConn, error) {
			return nil, nil
		},
	})
	if err == nil {
		t.Fatalf("expected BuildSnapshot to reject misconfigured route with validation error, got nil")
	}
}

func TestRouter_CORSPreflightOptionsBypassesAuth(t *testing.T) {
	reg := registry.NewRegistry()
	_ = reg.Register("auth", func(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
		_ = mux.HandlePath("POST", "/api/v1/auth/protected", func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		})
		return nil
	})

	mwReg := middleware.NewRegistry()
	_ = mwReg.Register("cors", builtins.NewCORSFactory())
	_ = mwReg.Register("authentication", func(cfg map[string]any) (middleware.Middleware, error) {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") == "" {
					middleware.WriteError(w, r, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
					return
				}
				next.ServeHTTP(w, r)
			})
		}, nil
	})

	cfg := &config.GatewayConfig{
		MiddlewareProfiles: map[string][]middleware.MiddlewareItem{
			"authenticated_api": {
				{Name: "cors"},
				{Name: "authentication"},
			},
		},
		Services: map[string]config.ServiceConfig{
			"auth": {
				Address: "mock:1234",
				Endpoints: []config.EndpointConfig{
					{
						Path:   "/api/v1/auth/protected",
						Method: "POST",
						Use:    []string{"authenticated_api"},
					},
				},
			},
		},
	}

	snap, err := BuildSnapshot(context.Background(), cfg, SnapshotOptions{
		Registry:           reg,
		MiddlewareRegistry: mwReg,
		Dialer: func(svc config.ServiceConfig) (*grpc.ClientConn, error) {
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("failed to build snapshot: %v", err)
	}
	defer snap.Retire()

	// 1. Unauthenticated POST to protected endpoint must return 401
	recPost := httptest.NewRecorder()
	reqPost := httptest.NewRequest(http.MethodPost, "/api/v1/auth/protected", nil)
	snap.Router().ServeHTTP(recPost, reqPost)
	if recPost.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated POST, got %d", recPost.Code)
	}

	// 2. Unauthenticated CORS preflight OPTIONS to protected endpoint must return 204 No Content without auth
	recOptions := httptest.NewRecorder()
	reqOptions := httptest.NewRequest(http.MethodOptions, "/api/v1/auth/protected", nil)
	reqOptions.Header.Set("Origin", "https://app.example.com")
	reqOptions.Header.Set("Access-Control-Request-Method", "POST")
	snap.Router().ServeHTTP(recOptions, reqOptions)
	if recOptions.Code != http.StatusNoContent {
		t.Fatalf("expected 204 No Content for CORS preflight OPTIONS, got %d", recOptions.Code)
	}
	if recOptions.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" {
		t.Errorf("expected Access-Control-Allow-Origin header, got %q", recOptions.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestRouter_NotFoundAndMethodNotAllowedJSON(t *testing.T) {
	reg := registry.NewRegistry()
	_ = reg.Register("test_svc", func(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
		_ = mux.HandlePath("POST", "/api/v1/items", func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
			w.WriteHeader(http.StatusOK)
		})
		return nil
	})

	cfg := &config.GatewayConfig{
		Services: map[string]config.ServiceConfig{
			"test_svc": {
				Address: "mock:1234",
				Endpoints: []config.EndpointConfig{
					{Path: "/api/v1/items", Method: "POST"},
				},
			},
		},
	}

	snap, err := BuildSnapshot(context.Background(), cfg, SnapshotOptions{
		Registry: reg,
		Dialer: func(svc config.ServiceConfig) (*grpc.ClientConn, error) {
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	defer snap.Retire()

	// 1. NotFound (404) returns JSON envelope
	rec404 := httptest.NewRecorder()
	req404 := httptest.NewRequest(http.MethodGet, "/api/v1/nonexistent", nil)
	snap.Router().ServeHTTP(rec404, req404)
	if rec404.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec404.Code)
	}
	if ct := rec404.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", ct)
	}

	// 2. MethodNotAllowed (405) returns JSON envelope
	rec405 := httptest.NewRecorder()
	req405 := httptest.NewRequest(http.MethodDelete, "/api/v1/items", nil)
	snap.Router().ServeHTTP(rec405, req405)
	if rec405.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec405.Code)
	}
	if ct := rec405.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", ct)
	}
}
