package registry

import (
	"context"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
)

func TestRegistry_RegisterAndGet(t *testing.T) {
	reg := NewRegistry()

	mockRegistrar := func(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
		return nil
	}

	err := reg.Register("test_service", mockRegistrar)
	if err != nil {
		t.Fatalf("unexpected error registering service: %v", err)
	}

	fn, ok := reg.Get("test_service")
	if !ok || fn == nil {
		t.Fatalf("expected to find test_service")
	}

	// Duplicate registration must fail
	err = reg.Register("test_service", mockRegistrar)
	if err == nil {
		t.Fatalf("expected duplicate registration error")
	}
}

func TestRegistry_Freeze(t *testing.T) {
	reg := NewRegistry()
	mockRegistrar := func(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
		return nil
	}

	reg.Freeze()
	if !reg.IsFrozen() {
		t.Errorf("expected registry to be frozen")
	}

	err := reg.Register("new_service", mockRegistrar)
	if err == nil {
		t.Fatalf("expected registration error on frozen registry")
	}
}

func TestDefaultRegistry_HasAuth(t *testing.T) {
	reg := DefaultRegistry()
	fn, ok := reg.Get("auth")
	if !ok || fn == nil {
		t.Fatalf("expected DefaultRegistry to have 'auth' registered")
	}
}
