package registry

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	githubv1 "github.com/skxm03/kr0n-backend/control-plane/gen/github/v1"
	servicemanagerv1 "github.com/skxm03/kr0n-backend/control-plane/gen/servicemanager/v1"
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
	{Method: "GET", Path: "/api/v1/auth/google/start"},
	{Method: "GET", Path: "/api/v1/auth/google/callback"},
	{Method: "POST", Path: "/api/v1/github/webhooks"},
}

// DefaultGitHubEndpoints provides the complete list of REST routes defined in github.proto.
var DefaultGitHubEndpoints = []EndpointDescriptor{
	{Method: "GET", Path: "/api/v1/orgs/{org_id}/github/repositories"},
	{Method: "GET", Path: "/api/v1/orgs/{org_id}/github/repositories/{owner}/{repo}/branches"},
	{Method: "GET", Path: "/api/v1/orgs/{org_id}/github/repositories/{owner}/{repo}/directories"},
}

// DefaultServiceManagerEndpoints provides the complete list of REST routes defined in servicemanager.proto.
var DefaultServiceManagerEndpoints = []EndpointDescriptor{
	{Method: "GET", Path: "/api/v1/presets"},
	{Method: "POST", Path: "/api/v1/orgs/{org_id}/projects"},
	{Method: "GET", Path: "/api/v1/orgs/{org_id}/projects"},
	{Method: "GET", Path: "/api/v1/orgs/{org_id}/projects/{project_id}"},
	{Method: "PATCH", Path: "/api/v1/orgs/{org_id}/projects/{project_id}"},
	{Method: "PUT", Path: "/api/v1/orgs/{org_id}/projects/{project_id}/build-settings"},
	{Method: "DELETE", Path: "/api/v1/orgs/{org_id}/projects/{project_id}"},
}

const defaultWebhookMaxBytes int64 = 10 << 20 // 10 MB

func resolveWebhookMaxBytes() int64 {
	if raw := strings.TrimSpace(os.Getenv("GITHUB_WEBHOOK_MAX_BYTES")); raw != "" {
		if n, err := strconv.ParseInt(raw, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return defaultWebhookMaxBytes
}

// DefaultRegistry creates and returns a Registry pre-populated with standard kr0n services.
func DefaultRegistry() *Registry {
	reg := NewRegistry()
	_ = reg.RegisterService("auth", ServiceRegistration{
		Registrar: func(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
			client := authv1.NewAuthServiceClient(conn)
			if err := authv1.RegisterAuthServiceHandlerClient(ctx, mux, client); err != nil {
				return err
			}
			// Mount custom raw-body handler for GitHub webhooks so exact payload bytes are preserved for HMAC-SHA256 verification.
			maxBytes := resolveWebhookMaxBytes()
			return mux.HandlePath("POST", "/api/v1/github/webhooks", func(w http.ResponseWriter, r *http.Request, _ map[string]string) {
				body, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
				if err != nil || int64(len(body)) > maxBytes {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusRequestEntityTooLarge)
					_, _ = w.Write([]byte(`{"error":"payload too large"}`))
					return
				}
				resp, err := client.HandleGitHubWebhook(r.Context(), &authv1.HandleGitHubWebhookRequest{
					Payload:         body,
					SignatureHeader: r.Header.Get("X-Hub-Signature-256"),
					EventType:       r.Header.Get("X-GitHub-Event"),
					DeliveryId:      r.Header.Get("X-GitHub-Delivery"),
				})
				if err != nil {
					w.Header().Set("Content-Type", "application/json")
					switch status.Code(err) {
					case codes.Unauthenticated:
						w.WriteHeader(http.StatusUnauthorized)
						_, _ = w.Write([]byte(`{"error":"invalid signature"}`))
					case codes.InvalidArgument:
						w.WriteHeader(http.StatusBadRequest)
						_, _ = w.Write([]byte(`{"error":"invalid payload"}`))
					case codes.ResourceExhausted:
						w.WriteHeader(http.StatusRequestEntityTooLarge)
						_, _ = w.Write([]byte(`{"error":"payload too large"}`))
					default:
						w.WriteHeader(http.StatusInternalServerError)
						_, _ = w.Write([]byte(`{"error":"internal processing error"}`))
					}
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				st := resp.GetStatus()
				if st == "" {
					st = "received"
				}
				_, _ = fmt.Fprintf(w, `{"status":%q}`, st)
			})
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
	_ = reg.RegisterService("servicemanager", ServiceRegistration{
		Registrar: func(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
			client := servicemanagerv1.NewServiceManagerServiceClient(conn)
			return servicemanagerv1.RegisterServiceManagerServiceHandlerClient(ctx, mux, client)
		},
		Endpoints: DefaultServiceManagerEndpoints,
	})
	return reg
}
