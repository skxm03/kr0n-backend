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

	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/dynamic/config"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/dynamic/registry"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
)

// MuxFactory creates a configured grpc-gateway ServeMux.
type MuxFactory func() *runtime.ServeMux

// ServiceDialer creates a gRPC client connection for a given service configuration.
type ServiceDialer func(svc config.ServiceConfig) (*grpc.ClientConn, error)

// SnapshotOptions configures the snapshot compilation process.
type SnapshotOptions struct {
	Registry           *registry.Registry
	MiddlewareRegistry *middleware.Registry
	MuxFactory         MuxFactory
	Dialer             ServiceDialer
	ReadyCheck         func(context.Context) error
}

// DefaultServiceDialer provides standard gRPC dialing with TLS/mTLS credentials.
func DefaultServiceDialer(svc config.ServiceConfig) (*grpc.ClientConn, error) {
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

	creds := credentials.NewTLS(tlsConfig)
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
// explicitly allowed endpoints wrapped with their compiled hierarchical middleware chains.
func BuildSnapshot(
	ctx context.Context,
	cfg *config.GatewayConfig,
	opts SnapshotOptions,
) (*Snapshot, error) {
	if cfg == nil {
		return nil, fmt.Errorf("gateway config cannot be nil")
	}
	if opts.Registry == nil {
		opts.Registry = registry.DefaultRegistry()
	}
	if opts.MiddlewareRegistry == nil {
		opts.MiddlewareRegistry = middleware.NewRegistry()
	}
	if opts.MuxFactory == nil {
		opts.MuxFactory = func() *runtime.ServeMux {
			return runtime.NewServeMux()
		}
	}
	if opts.Dialer == nil {
		opts.Dialer = DefaultServiceDialer
	}

	// 1. Compile profile resolver & chain compiler
	resolver, err := middleware.NewProfileResolver(cfg.MiddlewareProfiles)
	if err != nil {
		return nil, fmt.Errorf("initialize middleware profile resolver: %w", err)
	}
	compiler := middleware.NewChainCompiler(opts.MiddlewareRegistry, resolver)

	router := chi.NewRouter()

	// Global independent health and readiness endpoints
	router.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	router.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if opts.ReadyCheck != nil {
			checkCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()
			if err := opts.ReadyCheck(checkCtx); err != nil {
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

	// 2. Iterate services and compile hierarchical middleware
	for svcName, svc := range cfg.Services {
		if !svc.IsEnabled() {
			continue
		}

		registrar, found := opts.Registry.Get(svcName)
		if !found {
			cleanupOnErr()
			return nil, fmt.Errorf("no registrar found in registry for service %q", svcName)
		}

		conn, err := opts.Dialer(svc)
		if err != nil {
			cleanupOnErr()
			return nil, fmt.Errorf("failed to dial service %q (%s): %w", svcName, svc.Address, err)
		}
		conns = append(conns, conn)

		svcMux := opts.MuxFactory()
		if err := registrar(ctx, svcMux, conn); err != nil {
			cleanupOnErr()
			return nil, fmt.Errorf("failed to register grpc-gateway handlers for service %q: %w", svcName, err)
		}

		// Compile service groups
		var compiledGroups []middleware.CompiledGroup
		for gName, gCfg := range svc.Groups {
			grpItems := gCfg.Middleware
			if len(gCfg.Use) > 0 {
				pItems, err := resolver.Resolve(gCfg.Use)
				if err != nil {
					cleanupOnErr()
					return nil, fmt.Errorf("resolve group %q profiles: %w", gName, err)
				}
				grpItems = append(grpItems, pItems...)
			}

			var rules []middleware.GroupMatchRule
			for _, r := range gCfg.Match {
				methodsMap := make(map[string]bool)
				for _, m := range r.Methods {
					methodsMap[strings.ToUpper(strings.TrimSpace(m))] = true
				}
				rules = append(rules, middleware.GroupMatchRule{
					Path:    r.Path,
					Type:    middleware.MatchType(r.Type),
					Methods: methodsMap,
				})
			}

			compiledGroups = append(compiledGroups, middleware.CompiledGroup{
				Name:       gName,
				Rules:      rules,
				Middleware: grpItems,
			})
		}

		// Determine endpoints: if none specified in YAML, auto-populate from registry if enabled
		endpoints := svc.Endpoints
		if len(endpoints) == 0 && svc.IsAutoMount() {
			if sreg, ok := opts.Registry.GetService(svcName); ok && len(sreg.Endpoints) > 0 {
				for _, d := range sreg.Endpoints {
					endpoints = append(endpoints, config.EndpointConfig{
						Method: d.Method,
						Path:   d.Path,
					})
				}
			}
		}

		// Mount each allowed endpoint with its compiled chain
		optionsHandled := make(map[string]bool)
		for _, ep := range endpoints {
			timeout := ep.Timeout
			if timeout <= 0 {
				timeout = svc.Timeout
			}
			if timeout <= 0 {
				timeout = 10 * time.Second
			}

			baseHandler := TimeoutWrapper(svcMux, timeout)
			method := strings.ToUpper(strings.TrimSpace(ep.Method))
			path := strings.TrimSpace(ep.Path)

			endpointTarget := middleware.EndpointTarget{
				Method:     method,
				Path:       path,
				Use:        ep.Use,
				Middleware: ep.Middleware,
			}

			// Apply svc.DefaultProfile if endpoint has no custom policy and matches no groups
			if len(endpointTarget.Use) == 0 && len(endpointTarget.Middleware) == 0 && svc.DefaultProfile != "" {
				matchedGroup := false
				for _, grp := range compiledGroups {
					if grp.Matches(method, path) {
						matchedGroup = true
						break
					}
				}
				if !matchedGroup {
					endpointTarget.Use = []string{svc.DefaultProfile}
				}
			}

			// Compile 4-tier middleware chain: Global -> Service -> Group -> Endpoint
			compiledHandler, err := compiler.CompileEndpoint(
				baseHandler,
				cfg.Gateway.Middleware, // Global
				svc.Middleware,         // Service
				compiledGroups,         // Matching groups
				endpointTarget,         // Endpoint
			)
			if err != nil {
				cleanupOnErr()
				return nil, fmt.Errorf("compile middleware chain for %s %s: %w", method, path, err)
			}

			router.Method(method, path, compiledHandler)
			if !optionsHandled[path] {
				optionsHandled[path] = true
				router.Method(http.MethodOptions, path, compiledHandler)
			}
		}
	}

	return NewSnapshot(router, conns), nil
}
