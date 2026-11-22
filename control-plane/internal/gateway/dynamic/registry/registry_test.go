package registry

import (
	"context"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	githubv1 "github.com/skxm03/kr0n-backend/control-plane/gen/github/v1"
	secretsv1 "github.com/skxm03/kr0n-backend/control-plane/gen/secrets/v1"
	servicemanagerv1 "github.com/skxm03/kr0n-backend/control-plane/gen/servicemanager/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
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

func TestProtoReflection_DynamicEndpointExtraction(t *testing.T) {
	// 1. Auth service proto reflection
	authEndpoints := ExtractEndpointsFromFileDescriptor(authv1.File_auth_v1_auth_proto, "AuthService")
	if len(authEndpoints) != 34 {
		t.Fatalf("expected 34 endpoints extracted from auth.proto, got %d", len(authEndpoints))
	}

	authMap := make(map[string]bool)
	for _, ep := range authEndpoints {
		authMap[ep.Method+":"+ep.Path] = true
	}
	expectedAuthRoutes := []string{
		"POST:/api/v1/auth/register",
		"POST:/api/v1/auth/login",
		"POST:/api/v1/auth/refresh",
		"POST:/api/v1/auth/logout",
		"GET:/api/v1/me",
		"GET:/api/v1/auth/jwks",
		"GET:/api/v1/auth/github/callback",
		"POST:/api/v1/orgs",
		"GET:/api/v1/orgs/{org_id}/members",
	}
	for _, r := range expectedAuthRoutes {
		if !authMap[r] {
			t.Errorf("expected route %s to be extracted from auth.proto, but was missing", r)
		}
	}

	// 2. GitHub service proto reflection
	ghEndpoints := ExtractEndpointsFromFileDescriptor(githubv1.File_github_v1_github_proto, "GitHubService")
	if len(ghEndpoints) != 7 {
		t.Fatalf("expected 7 endpoints extracted from github.proto, got %d", len(ghEndpoints))
	}

	// 3. ServiceManager proto reflection
	smEndpoints := ExtractEndpointsFromFileDescriptor(servicemanagerv1.File_servicemanager_v1_servicemanager_proto, "ServiceManagerService")
	if len(smEndpoints) != 7 {
		t.Fatalf("expected 7 endpoints extracted from servicemanager.proto, got %d", len(smEndpoints))
	}

	// 4. Secrets proto reflection
	secEndpoints := ExtractEndpointsFromFileDescriptor(secretsv1.File_secrets_v1_secrets_proto, "SecretsService")
	if len(secEndpoints) != 3 {
		t.Fatalf("expected 3 endpoints extracted from secrets.proto, got %d", len(secEndpoints))
	}
}

func TestProtoReflection_InternalServicesExcluded(t *testing.T) {
	// SecretsInternalService (ResolveProjectSecrets) is internal and MUST NOT have perimeter endpoints.
	internalEndpoints := ExtractEndpointsFromFileDescriptor(secretsv1.File_secrets_v1_secrets_proto, "SecretsInternalService")
	if len(internalEndpoints) != 0 {
		t.Fatalf("expected 0 endpoints extracted for SecretsInternalService, got %d", len(internalEndpoints))
	}

	// DefaultSecretsEndpoints must only expose SecretsService
	for _, ep := range DefaultSecretsEndpoints {
		if ep.Path == "/api/v1/internal/secrets" || ep.Path == "/resolve-project-secrets" {
			t.Fatalf("internal secret route leaked into DefaultSecretsEndpoints: %s %s", ep.Method, ep.Path)
		}
	}
}

func TestProtoReflection_DecorateEndpoints(t *testing.T) {
	rawEndpoints := []EndpointDescriptor{
		{Method: "GET", Path: "/api/v1/auth/github/callback"},
		{Method: "POST", Path: "/api/v1/auth/login"},
	}

	decorated := DecorateEndpoints(rawEndpoints, map[string][]middleware.MiddlewareItem{
		"GET:/api/v1/auth/github/callback": {
			{Name: "github_app_callback"},
		},
	})

	if len(decorated) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(decorated))
	}
	if len(decorated[0].DefaultMiddleware) != 1 || decorated[0].DefaultMiddleware[0].Name != "github_app_callback" {
		t.Errorf("expected github_app_callback middleware on callback endpoint, got %+v", decorated[0].DefaultMiddleware)
	}
	if len(decorated[1].DefaultMiddleware) != 0 {
		t.Errorf("expected no middleware on login endpoint, got %+v", decorated[1].DefaultMiddleware)
	}
}

func TestDefaultRegistry_CatalogAndAutoMountAlignment(t *testing.T) {
	reg := DefaultRegistry()

	services := []string{"auth", "github", "servicemanager", "secrets"}
	for _, s := range services {
		if !reg.HasService(s) {
			t.Errorf("expected DefaultRegistry to have service %q", s)
		}
		eps, ok := reg.GetServiceEndpoints(s)
		if !ok || len(eps) == 0 {
			t.Errorf("expected DefaultRegistry to provide non-empty endpoints for %q", s)
		}
	}

	// Verify GitHub has 8 endpoints (7 proto + 1 raw webhook)
	ghEps, _ := reg.GetServiceEndpoints("github")
	if len(ghEps) != 8 {
		t.Errorf("expected 8 endpoints for github (including raw webhook), got %d", len(ghEps))
	}

	// Verify Auth callback has middleware decorated
	sreg, ok := reg.GetService("auth")
	if !ok {
		t.Fatalf("expected to get auth service registration")
	}
	foundCallbackWithMiddleware := false
	for _, ep := range sreg.Endpoints {
		if ep.Method == "GET" && ep.Path == "/api/v1/auth/github/callback" {
			for _, mw := range ep.DefaultMiddleware {
				if mw.Name == "github_app_callback" {
					foundCallbackWithMiddleware = true
				}
			}
		}
	}
	if !foundCallbackWithMiddleware {
		t.Errorf("expected auth /api/v1/auth/github/callback to have github_app_callback default middleware")
	}
}
