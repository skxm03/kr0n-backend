package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware/builtins"
)

func TestRegistry_RegisterAndBuild(t *testing.T) {
	reg := middleware.NewRegistry()

	err := builtins.RegisterDefaults(reg, builtins.SharedDeps{})
	if err != nil {
		t.Fatalf("failed to register defaults: %v", err)
	}

	// Duplicate registration must fail
	err = reg.Register("cors", builtins.NewCORSFactory())
	if err == nil {
		t.Fatalf("expected error on duplicate registration, got nil")
	}

	// Build valid middleware
	mw, err := reg.Build("cors", map[string]any{
		"allow_credentials": true,
	})
	if err != nil {
		t.Fatalf("failed to build cors: %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "http://example.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected 204 for OPTIONS preflight, got %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Errorf("expected credentials header true, got %s", rec.Header().Get("Access-Control-Allow-Credentials"))
	}

	// Unknown middleware must fail
	_, err = reg.Build("unknown_middleware", nil)
	if err == nil {
		t.Fatalf("expected error for unknown middleware")
	}

	// Freeze
	reg.Freeze()
	if !reg.IsFrozen() {
		t.Errorf("expected registry to be frozen")
	}
	err = reg.Register("another", func(cfg map[string]any) (middleware.Middleware, error) {
		return nil, nil
	})
	if err == nil {
		t.Fatalf("expected error registering on frozen registry")
	}
}
