package middleware

import (
	"fmt"
	"sync"
)

// MiddlewareFactory constructs an executable Middleware from a configuration map.
type MiddlewareFactory func(config map[string]any) (Middleware, error)

// Registry manages the available middleware factories and freezes upon initialization.
type Registry struct {
	mu        sync.RWMutex
	frozen    bool
	factories map[string]MiddlewareFactory
}

// NewRegistry initializes an empty middleware Registry.
func NewRegistry() *Registry {
	return &Registry{
		factories: make(map[string]MiddlewareFactory),
	}
}

// Register binds a middleware name to a factory. Fails if frozen or already registered.
func (r *Registry) Register(name string, factory MiddlewareFactory) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.frozen {
		return fmt.Errorf("cannot register middleware %q: registry is frozen", name)
	}
	if factory == nil {
		return fmt.Errorf("factory for %q cannot be nil", name)
	}
	if _, exists := r.factories[name]; exists {
		return fmt.Errorf("middleware %q is already registered", name)
	}

	r.factories[name] = factory
	return nil
}

// Build creates a Middleware instance for the given name and configuration.
func (r *Registry) Build(name string, config map[string]any) (Middleware, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	factory, ok := r.factories[name]
	if !ok {
		return nil, fmt.Errorf("unknown middleware %q: not registered", name)
	}

	return factory(config)
}

// Freeze marks the registry as frozen, preventing further registrations.
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
