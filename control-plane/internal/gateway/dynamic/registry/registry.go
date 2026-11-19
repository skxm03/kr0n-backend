package registry

import (
	"context"
	"fmt"
	"sync"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	githubv1 "github.com/skxm03/kr0n-backend/control-plane/gen/github/v1"
)

// ServiceRegistrar binds a gRPC client connection to a grpc-gateway ServeMux.
type ServiceRegistrar func(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error

// EndpointDescriptor describes a known HTTP route supported by a service.
type EndpointDescriptor struct {
	Method string
	Path   string
}

// ServiceRegistration holds a registrar and its optional list of default known endpoints.
type ServiceRegistration struct {
	Registrar ServiceRegistrar
	Endpoints []EndpointDescriptor
}

// Registry maintains the mapping between service names and their compiled grpc-gateway registrars.
type Registry struct {
	mu       sync.RWMutex
	frozen   bool
	services map[string]ServiceRegistration
}

// NewRegistry initializes an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		services: make(map[string]ServiceRegistration),
	}
}

// RegisterService adds a service with its registrar and optional endpoints.
func (r *Registry) RegisterService(name string, reg ServiceRegistration) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.frozen {
		return fmt.Errorf("cannot register service %q: registry is frozen", name)
	}
	if reg.Registrar == nil {
		return fmt.Errorf("service registrar for %q cannot be nil", name)
	}
	if _, exists := r.services[name]; exists {
		return fmt.Errorf("service %q is already registered", name)
	}

	r.services[name] = reg
	return nil
}

// Register adds a service registrar to the registry without default endpoints.
func (r *Registry) Register(name string, registrar ServiceRegistrar) error {
	return r.RegisterService(name, ServiceRegistration{Registrar: registrar})
}

// GetService retrieves a service registration by name.
func (r *Registry) GetService(name string) (ServiceRegistration, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	reg, ok := r.services[name]
	return reg, ok
}

// Get retrieves a service registrar by name.
func (r *Registry) Get(name string) (ServiceRegistrar, bool) {
	reg, ok := r.GetService(name)
	if !ok {
		return nil, false
	}
	return reg.Registrar, true
}

// Freeze prevents any future registrations.
func (r *Registry) Freeze() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.frozen = true
}

// IsFrozen reports whether the registry is frozen.
func (r *Registry) IsFrozen() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.frozen
}

// DefaultAuthEndpoints provides the complete list of REST routes defined in auth.proto.
var DefaultAuthEndpoints = []EndpointDescriptor{
	{Method: "POST", Path: "/api/v1/auth/register"},
	{Method: "POST", Path: "/api/v1/auth/login"},
	{Method: "POST", Path: "/api/v1/auth/refresh"},
	{Method: "POST", Path: "/api/v1/auth/logout"},
	{Method: "POST", Path: "/api/v1/auth/verify-email"},
	{Method: "POST", Path: "/api/v1/auth/resend-verification"},
	{Method: "POST", Path: "/api/v1/auth/password-reset/request"},
	{Method: "POST", Path: "/api/v1/auth/password-reset/confirm"},
	{Method: "POST", Path: "/api/v1/auth/password/change"},
	{Method: "GET", Path: "/api/v1/me"},
	{Method: "GET", Path: "/api/v1/auth/sessions"},
	{Method: "DELETE", Path: "/api/v1/auth/sessions/{session_id}"},
	{Method: "GET", Path: "/api/v1/roles"},
	{Method: "POST", Path: "/api/v1/orgs"},
	{Method: "GET", Path: "/api/v1/orgs"},
	{Method: "GET", Path: "/api/v1/orgs/{org_id}"},
	{Method: "PATCH", Path: "/api/v1/orgs/{org_id}"},
	{Method: "DELETE", Path: "/api/v1/orgs/{org_id}"},
	{Method: "GET", Path: "/api/v1/orgs/{org_id}/members"},
	{Method: "POST", Path: "/api/v1/orgs/{org_id}/members"},
	{Method: "PATCH", Path: "/api/v1/orgs/{org_id}/members/{target_user_id}"},
	{Method: "DELETE", Path: "/api/v1/orgs/{org_id}/members/{target_user_id}"},
	{Method: "POST", Path: "/api/v1/orgs/{org_id}/invites"},
	{Method: "POST", Path: "/api/v1/orgs/invites/accept"},
	{Method: "DELETE", Path: "/api/v1/orgs/{org_id}/invites/{invite_id}"},
	{Method: "POST", Path: "/api/v1/orgs/{org_id}/tokens"},
	{Method: "GET", Path: "/api/v1/orgs/{org_id}/tokens"},
	{Method: "DELETE", Path: "/api/v1/orgs/{org_id}/tokens/{token_id}"},
	{Method: "GET", Path: "/api/v1/orgs/{org_id}/audit"},
	{Method: "GET", Path: "/api/v1/orgs/{org_id}/github/installations/start"},
	{Method: "POST", Path: "/api/v1/orgs/{org_id}/github/installations"},
	{Method: "GET", Path: "/api/v1/orgs/{org_id}/github/installations"},
	{Method: "DELETE", Path: "/api/v1/orgs/{org_id}/github/installations/{installation_id}"},
	{Method: "GET", Path: "/api/v1/auth/jwks"},
	{Method: "GET", Path: "/api/v1/auth/github/start"},
	{Method: "GET", Path: "/api/v1/auth/github/callback"},
}

// DefaultGitHubEndpoints provides the complete list of REST routes defined in github.proto.
var DefaultGitHubEndpoints = []EndpointDescriptor{
	{Method: "GET", Path: "/api/v1/orgs/{org_id}/github/repositories"},
	{Method: "GET", Path: "/api/v1/orgs/{org_id}/github/repositories/{owner}/{repo}/branches"},
	{Method: "GET", Path: "/api/v1/orgs/{org_id}/github/repositories/{owner}/{repo}/directories"},
}

// DefaultRegistry creates and returns a Registry pre-populated with standard kr0n services.
func DefaultRegistry() *Registry {
	reg := NewRegistry()
	_ = reg.RegisterService("auth", ServiceRegistration{
		Registrar: func(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
			client := authv1.NewAuthServiceClient(conn)
			return authv1.RegisterAuthServiceHandlerClient(ctx, mux, client)
		},
		Endpoints: DefaultAuthEndpoints,
	})
	_ = reg.RegisterService("github", ServiceRegistration{
		Registrar: func(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
			client := githubv1.NewGitHubServiceClient(conn)
			return githubv1.RegisterGitHubServiceHandlerClient(ctx, mux, client)
		},
		Endpoints: DefaultGitHubEndpoints,
	})
	return reg
}
