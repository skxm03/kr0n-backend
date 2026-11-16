package registry

import (
	"context"
	"fmt"
	"sync"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
)

// ServiceRegistrar binds a gRPC client connection to a grpc-gateway ServeMux.
type ServiceRegistrar func(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error

// Registry maintains the mapping between service names and their compiled grpc-gateway registrars.
type Registry struct {
	mu         sync.RWMutex
	frozen     bool
	registrars map[string]ServiceRegistrar
}

// NewRegistry initializes an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		registrars: make(map[string]ServiceRegistrar),
	}
}

// Register adds a service registrar to the registry. Fails if registry is frozen or name exists.
func (r *Registry) Register(name string, registrar ServiceRegistrar) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.frozen {
		return fmt.Errorf("cannot register service %q: registry is frozen", name)
	}
	if registrar == nil {
		return fmt.Errorf("service registrar for %q cannot be nil", name)
	}
	if _, exists := r.registrars[name]; exists {
		return fmt.Errorf("service %q is already registered", name)
	}

	r.registrars[name] = registrar
	return nil
}

// Get retrieves a service registrar by name.
func (r *Registry) Get(name string) (ServiceRegistrar, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	reg, ok := r.registrars[name]
	return reg, ok
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

// DefaultRegistry creates and returns a Registry pre-populated with standard kr0n services.
func DefaultRegistry() *Registry {
	reg := NewRegistry()
	_ = reg.Register("auth", func(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
		client := authv1.NewAuthServiceClient(conn)
		return authv1.RegisterAuthServiceHandlerClient(ctx, mux, client)
	})
	return reg
}
