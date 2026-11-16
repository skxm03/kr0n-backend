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

	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/dynamic/config"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/dynamic/registry"
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

	snap, err := BuildSnapshot(context.Background(), cfg, reg, nil, mockDialer, nil)
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
