package router

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/dynamic/config"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/dynamic/registry"
)

// MuxFactory creates a configured grpc-gateway ServeMux.
type MuxFactory func() *runtime.ServeMux

// ServiceDialer creates a gRPC client connection for a given service configuration.
type ServiceDialer func(svc config.ServiceConfig) (*grpc.ClientConn, error)

// DefaultServiceDialer provides standard gRPC dialing with TLS or insecure credentials.
func DefaultServiceDialer(svc config.ServiceConfig) (*grpc.ClientConn, error) {
	var creds credentials.TransportCredentials

	if svc.TLS.Enabled {
		tlsConfig := &tls.Config{
			ServerName: svc.TLS.ServerName,
			MinVersion: tls.VersionTLS12,
		}

		if svc.TLS.CertFile != "" && svc.TLS.KeyFile != "" {
			cert, err := tls.LoadX509KeyPair(svc.TLS.CertFile, svc.TLS.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("load tls client cert: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}

		if svc.TLS.CAFile != "" {
			caPEM, err := os.ReadFile(svc.TLS.CAFile)
			if err != nil {
				return nil, fmt.Errorf("read tls ca file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caPEM) {
				return nil, fmt.Errorf("parse ca cert: no valid certificates found")
			}
			tlsConfig.RootCAs = pool
		}

		creds = credentials.NewTLS(tlsConfig)
	} else {
		creds = insecure.NewCredentials()
	}

	return grpc.NewClient(svc.Address, grpc.WithTransportCredentials(creds))
}

// TimeoutWrapper wraps an http.Handler to enforce a context deadline for the request.
// grpc-gateway automatically propagates this context deadline to upstream gRPC RPCs.
func TimeoutWrapper(next http.Handler, timeout time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// BuildSnapshot constructs an immutable Snapshot from the GatewayConfig.
// It dials enabled services, binds their grpc-gateway ServeMuxes, and mounts only
// explicitly allowed endpoints on an outer Chi router.
func BuildSnapshot(
	ctx context.Context,
	cfg *config.GatewayConfig,
	reg *registry.Registry,
	muxFactory MuxFactory,
	dialer ServiceDialer,
	readyCheck func(context.Context) error,
) (*Snapshot, error) {
	if cfg == nil {
		return nil, fmt.Errorf("gateway config cannot be nil")
	}
	if reg == nil {
		return nil, fmt.Errorf("service registry cannot be nil")
	}
	if muxFactory == nil {
		muxFactory = func() *runtime.ServeMux {
			return runtime.NewServeMux()
		}
	}
	if dialer == nil {
		dialer = DefaultServiceDialer
	}

	router := chi.NewRouter()

	// Global independent health and readiness endpoints
	router.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	router.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if readyCheck != nil {
			checkCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()
			if err := readyCheck(checkCtx); err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"status": "unavailable",
					"error":  err.Error(),
				})
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
	})

	var conns []*grpc.ClientConn
	cleanupOnErr := func() {
		for _, c := range conns {
			if c != nil {
				_ = c.Close()
			}
		}
	}

	// Iterate services and mount only allowed endpoints
	for svcName, svc := range cfg.Services {
		if !svc.IsEnabled() {
			continue
		}

		registrar, found := reg.Get(svcName)
		if !found {
			cleanupOnErr()
			return nil, fmt.Errorf("no registrar found in registry for service %q", svcName)
		}

		conn, err := dialer(svc)
		if err != nil {
			cleanupOnErr()
			return nil, fmt.Errorf("failed to dial service %q (%s): %w", svcName, svc.Address, err)
		}
		conns = append(conns, conn)

		svcMux := muxFactory()
		if err := registrar(ctx, svcMux, conn); err != nil {
			cleanupOnErr()
			return nil, fmt.Errorf("failed to register grpc-gateway handlers for service %q: %w", svcName, err)
		}

		// Mount each allowed endpoint
		for _, ep := range svc.Endpoints {
			timeout := ep.Timeout
			if timeout <= 0 {
				timeout = svc.Timeout
			}
			if timeout <= 0 {
				timeout = 10 * time.Second
			}

			handler := TimeoutWrapper(svcMux, timeout)
			method := strings.ToUpper(strings.TrimSpace(ep.Method))
			path := strings.TrimSpace(ep.Path)

			router.Method(method, path, handler)
		}
	}

	return NewSnapshot(router, conns), nil
}
