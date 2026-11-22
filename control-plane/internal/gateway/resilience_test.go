package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/dynamic/config"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/dynamic/registry"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/dynamic/router"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
)

// 1. Unreachable upstream service: Gateway must return 503 SERVICE_UNAVAILABLE
func TestGatewayResilience_UnreachableUpstream(t *testing.T) {
	// Pick an open local port and immediately close the listener so nothing is listening
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	deadAddr := lis.Addr().String()
	_ = lis.Close()

	reg := registry.NewRegistry()
	_ = reg.Register("test_svc", func(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
		// Mock handler that attempts to call the dead connection
		return mux.HandlePath("GET", "/api/v1/test", func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
			// Simulate what grpc-gateway does when dial target is unreachable
			var dummyReply any
			err := conn.Invoke(r.Context(), "/test.Service/TestMethod", nil, dummyReply)
			if err != nil {
				GatewayErrorHandler(r.Context(), mux, nil, w, r, err)
			}
		})
	})

	cfg := &config.GatewayConfig{
		Services: map[string]config.ServiceConfig{
			"test_svc": {
				Address: deadAddr,
				Timeout: 2 * time.Second,
				Endpoints: []config.EndpointConfig{
					{Method: "GET", Path: "/api/v1/test"},
				},
			},
		},
	}

	dialer := func(svc config.ServiceConfig) (*grpc.ClientConn, error) {
		return grpc.NewClient(svc.Address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	snap, err := router.BuildSnapshot(context.Background(), cfg, router.SnapshotOptions{
		Registry: reg,
		Dialer:   dialer,
	})
	if err != nil {
		t.Fatalf("failed to build snapshot: %v", err)
	}
	defer snap.WaitAndClose(1 * time.Second)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	rec := httptest.NewRecorder()
	snap.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 Service Unavailable, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	var errDTO ErrorResponseDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &errDTO); err != nil {
		t.Fatalf("failed to parse JSON error: %v", err)
	}
	if errDTO.Code != "SERVICE_UNAVAILABLE" {
		t.Fatalf("expected error code SERVICE_UNAVAILABLE, got %q", errDTO.Code)
	}
}

// 2. Upstream timeout: Gateway must return 504 GATEWAY_TIMEOUT when upstream exceeds deadline
func TestGatewayResilience_UpstreamTimeout(t *testing.T) {
	reg := registry.NewRegistry()
	_ = reg.Register("slow_svc", func(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
		return mux.HandlePath("GET", "/api/v1/slow", func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
			select {
			case <-time.After(500 * time.Millisecond):
				w.WriteHeader(http.StatusOK)
			case <-r.Context().Done():
				// Context expired due to TimeoutWrapper
				err := status.Error(codes.DeadlineExceeded, "context deadline exceeded")
				GatewayErrorHandler(r.Context(), mux, nil, w, r, err)
			}
		})
	})

	// Configure a tight 50ms timeout for this endpoint
	cfg := &config.GatewayConfig{
		Services: map[string]config.ServiceConfig{
			"slow_svc": {
				Address: "mock:1234",
				Timeout: 50 * time.Millisecond,
				Endpoints: []config.EndpointConfig{
					{Method: "GET", Path: "/api/v1/slow", Timeout: 50 * time.Millisecond},
				},
			},
		},
	}

	snap, err := router.BuildSnapshot(context.Background(), cfg, router.SnapshotOptions{
		Registry: reg,
		Dialer: func(svc config.ServiceConfig) (*grpc.ClientConn, error) {
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("failed to build snapshot: %v", err)
	}
	defer snap.WaitAndClose(1 * time.Second)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/slow", nil)
	rec := httptest.NewRecorder()
	snap.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("expected 504 Gateway Timeout, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	var errDTO ErrorResponseDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &errDTO); err != nil {
		t.Fatalf("failed to parse JSON error: %v", err)
	}
	if errDTO.Code != "GATEWAY_TIMEOUT" {
		t.Fatalf("expected error code GATEWAY_TIMEOUT, got %q", errDTO.Code)
	}
}

// 3. Invalid config safety: Rejects bad config and protects active traffic without dropping packets
func TestGatewayResilience_InvalidConfigRejected_ProtectsActiveTraffic(t *testing.T) {
	reg := registry.NewRegistry()
	_ = reg.Register("auth", func(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
		return mux.HandlePath("GET", "/api/v1/me", func(w http.ResponseWriter, r *http.Request, _ map[string]string) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"healthy"}`))
		})
	})

	mgr := router.NewManager(router.ManagerOptions{
		Registry: reg,
		Dialer: func(svc config.ServiceConfig) (*grpc.ClientConn, error) {
			return nil, nil
		},
	})
	defer mgr.Close()

	// Initial valid config
	validCfg := &config.GatewayConfig{
		Services: map[string]config.ServiceConfig{
			"auth": {
				Address: "mock:50051",
				Endpoints: []config.EndpointConfig{
					{Method: "GET", Path: "/api/v1/me"},
				},
			},
		},
	}
	if err := mgr.Initialize(context.Background(), validCfg); err != nil {
		t.Fatalf("failed to initialize manager: %v", err)
	}

	// Verify active router serves 200
	rec := httptest.NewRecorder()
	mgr.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/me", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on active config, got %d", rec.Code)
	}

	// Case A: Reload with bad config: unregistered service
	badCfg1 := &config.GatewayConfig{
		Services: map[string]config.ServiceConfig{
			"unknown_service_xyz": {
				Address: "mock:9999",
				Endpoints: []config.EndpointConfig{
					{Method: "GET", Path: "/api/v1/unknown"},
				},
			},
		},
	}
	if err := mgr.Reload(context.Background(), badCfg1); err == nil {
		t.Fatal("expected reload error for unregistered service, got nil")
	}

	// Case B: Reload with dialer error (e.g. invalid TLS)
	badDialMgr := router.NewManager(router.ManagerOptions{
		Registry: reg,
		Dialer: func(svc config.ServiceConfig) (*grpc.ClientConn, error) {
			return nil, errors.New("tls handshake failed: certificate expired")
		},
	})
	defer badDialMgr.Close()
	if err := badDialMgr.Initialize(context.Background(), validCfg); err == nil {
		t.Fatal("expected initialization error when dialer fails, got nil")
	}

	// Verify that the original manager is STILL healthy and unaffected
	recAfterBadReload := httptest.NewRecorder()
	mgr.ServeHTTP(recAfterBadReload, httptest.NewRequest(http.MethodGet, "/api/v1/me", nil))
	if recAfterBadReload.Code != http.StatusOK || recAfterBadReload.Body.String() != `{"status":"healthy"}` {
		t.Fatalf("active snapshot was corrupted by failed reload: status=%d body=%s",
			recAfterBadReload.Code, recAfterBadReload.Body.String())
	}
}

// 4. Client cancellation mid-flight: Gateway propagates context cancellation to upstream
func TestGatewayResilience_ClientMidFlightCancellation(t *testing.T) {
	upstreamCanceled := make(chan struct{})

	reg := registry.NewRegistry()
	_ = reg.Register("cancel_svc", func(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
		return mux.HandlePath("POST", "/api/v1/heavy-work", func(w http.ResponseWriter, r *http.Request, _ map[string]string) {
			select {
			case <-time.After(2 * time.Second):
				w.WriteHeader(http.StatusOK)
			case <-r.Context().Done():
				// Context was canceled by the client disconnecting!
				close(upstreamCanceled)
				w.WriteHeader(499) // Client Closed Request
			}
		})
	})

	cfg := &config.GatewayConfig{
		Services: map[string]config.ServiceConfig{
			"cancel_svc": {
				Address: "mock:1234",
				Timeout: 5 * time.Second,
				Endpoints: []config.EndpointConfig{
					{Method: "POST", Path: "/api/v1/heavy-work"},
				},
			},
		},
	}

	snap, err := router.BuildSnapshot(context.Background(), cfg, router.SnapshotOptions{
		Registry: reg,
		Dialer: func(svc config.ServiceConfig) (*grpc.ClientConn, error) {
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("build snapshot error: %v", err)
	}
	defer snap.WaitAndClose(1 * time.Second)

	// Create request with cancelable context
	reqCtx, cancelReq := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/heavy-work", nil).WithContext(reqCtx)
	rec := httptest.NewRecorder()

	go func() {
		// Simulate client disconnecting after 50ms
		time.Sleep(50 * time.Millisecond)
		cancelReq()
	}()

	snap.Router().ServeHTTP(rec, req)

	select {
	case <-upstreamCanceled:
		// Upstream successfully notified of client disconnection!
	case <-time.After(1 * time.Second):
		t.Fatal("upstream handler did not receive context cancellation when client disconnected")
	}
}

// 5. In-flight request draining during reload: In-flight requests are NOT severed when config is swapped
func TestGatewayResilience_InFlightRequestsDrainedDuringReload(t *testing.T) {
	var inFlightStarted sync.WaitGroup
	inFlightStarted.Add(1)

	var inFlightCanFinish sync.WaitGroup
	inFlightCanFinish.Add(1)

	var v1Served int32
	var v2Served int32

	reg := registry.NewRegistry()
	_ = reg.Register("app", func(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
		_ = mux.HandlePath("GET", "/api/v1/work", func(w http.ResponseWriter, r *http.Request, _ map[string]string) {
			v := r.Header.Get("X-Config-Version")
			if v == "v1" {
				atomic.AddInt32(&v1Served, 1)
				inFlightStarted.Done()
				inFlightCanFinish.Wait() // Wait until reload happens before finishing
			} else {
				atomic.AddInt32(&v2Served, 1)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(v))
		})
		return nil
	})

	mwReg := middleware.NewRegistry()
	_ = mwReg.Register("header_v1", func(cfg map[string]any) (middleware.Middleware, error) {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.Header.Set("X-Config-Version", "v1")
				next.ServeHTTP(w, r)
			})
		}, nil
	})
	_ = mwReg.Register("header_v2", func(cfg map[string]any) (middleware.Middleware, error) {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.Header.Set("X-Config-Version", "v2")
				next.ServeHTTP(w, r)
			})
		}, nil
	})

	mgr := router.NewManager(router.ManagerOptions{
		Registry:           reg,
		MiddlewareRegistry: mwReg,
		Dialer: func(svc config.ServiceConfig) (*grpc.ClientConn, error) {
			return nil, nil
		},
		SafetyTimeout: 5 * time.Second,
	})
	defer mgr.Close()

	cfgV1 := &config.GatewayConfig{
		Services: map[string]config.ServiceConfig{
			"app": {
				Address: "mock:1234",
				Endpoints: []config.EndpointConfig{
					{
						Method: "GET",
						Path:   "/api/v1/work",
						Middleware: []middleware.MiddlewareItem{
							{Name: "header_v1"},
						},
					},
				},
			},
		},
	}

	if err := mgr.Initialize(context.Background(), cfgV1); err != nil {
		t.Fatalf("initialize error: %v", err)
	}

	// Start long-running in-flight request on v1
	v1Done := make(chan struct{})
	v1Rec := httptest.NewRecorder()
	go func() {
		mgr.ServeHTTP(v1Rec, httptest.NewRequest("GET", "/api/v1/work", nil))
		close(v1Done)
	}()

	// Wait for the request to enter the handler
	inFlightStarted.Wait()

	// While request is in-flight, perform a hot reload to v2!
	cfgV2 := &config.GatewayConfig{
		Services: map[string]config.ServiceConfig{
			"app": {
				Address: "mock:1234",
				Endpoints: []config.EndpointConfig{
					{
						Method: "GET",
						Path:   "/api/v1/work",
						Middleware: []middleware.MiddlewareItem{
							{Name: "header_v2"},
						},
					},
				},
			},
		},
	}
	if err := mgr.Reload(context.Background(), cfgV2); err != nil {
		t.Fatalf("reload error: %v", err)
	}

	// Release the in-flight v1 request to finish
	inFlightCanFinish.Done()

	select {
	case <-v1Done:
		if v1Rec.Code != http.StatusOK || v1Rec.Body.String() != "v1" {
			t.Fatalf("expected in-flight request to complete successfully on v1, got status=%d body=%s",
				v1Rec.Code, v1Rec.Body.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight request timed out after reload")
	}

	// New requests must be routed to v2
	v2Rec := httptest.NewRecorder()
	mgr.ServeHTTP(v2Rec, httptest.NewRequest("GET", "/api/v1/work", nil))
	if v2Rec.Code != http.StatusOK || v2Rec.Body.String() != "v2" {
		t.Fatalf("expected new request to route to v2, got status=%d body=%s", v2Rec.Code, v2Rec.Body.String())
	}
}
