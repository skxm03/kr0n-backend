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
	"google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	githubv1 "github.com/skxm03/kr0n-backend/control-plane/gen/github/v1"
	secretsv1 "github.com/skxm03/kr0n-backend/control-plane/gen/secrets/v1"
	servicemanagerv1 "github.com/skxm03/kr0n-backend/control-plane/gen/servicemanager/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/dynamic/config"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
)

// ServiceRegistrar binds a gRPC client connection to a grpc-gateway ServeMux.
type ServiceRegistrar func(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error

// EndpointDescriptor describes a known HTTP route supported by a service.
type EndpointDescriptor struct {
	Method            string
	Path              string
	DefaultMiddleware []middleware.MiddlewareItem
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

// Compile-time assertion that *Registry implements config.ServiceCatalog.
var _ config.ServiceCatalog = (*Registry)(nil)

// HasService reports whether a service is registered.
func (r *Registry) HasService(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.services[name]
	return ok
}

// GetServiceEndpoints returns all known route descriptors for a service.
func (r *Registry) GetServiceEndpoints(name string) ([]config.RouteDescriptor, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	reg, ok := r.services[name]
	if !ok {
		return nil, false
	}
	out := make([]config.RouteDescriptor, len(reg.Endpoints))
	for i, ep := range reg.Endpoints {
		out[i] = config.RouteDescriptor{
			Method: ep.Method,
			Path:   ep.Path,
		}
	}
	return out, true
}

// ExtractEndpointsFromFileDescriptor reflects over a compiled protobuf FileDescriptor
// and extracts all HTTP endpoints declared via (google.api.http) annotations.
// If serviceNames are specified, only methods belonging to those services are extracted.
// Service names can be simple ("AuthService") or fully-qualified ("auth.v1.AuthService").
func ExtractEndpointsFromFileDescriptor(fd protoreflect.FileDescriptor, serviceNames ...string) []EndpointDescriptor {
	if fd == nil {
		return nil
	}

	filter := make(map[string]bool)
	for _, s := range serviceNames {
		sClean := strings.ToLower(strings.TrimSpace(s))
		if sClean != "" {
			filter[sClean] = true
		}
	}

	var endpoints []EndpointDescriptor
	seen := make(map[string]bool)

	services := fd.Services()
	for i := 0; i < services.Len(); i++ {
		svc := services.Get(i)
		svcName := string(svc.Name())
		svcFullName := string(svc.FullName())

		if len(filter) > 0 {
			if !filter[strings.ToLower(svcName)] && !filter[strings.ToLower(svcFullName)] {
				continue
			}
		}

		methods := svc.Methods()
		for j := 0; j < methods.Len(); j++ {
			m := methods.Get(j)
			opts := m.Options()
			if !proto.HasExtension(opts, annotations.E_Http) {
				continue
			}

			ext := proto.GetExtension(opts, annotations.E_Http)
			rule, ok := ext.(*annotations.HttpRule)
			if !ok || rule == nil {
				continue
			}

			for _, ep := range extractHTTPRuleBindings(rule) {
				key := ep.Method + ":" + ep.Path
				if !seen[key] {
					seen[key] = true
					endpoints = append(endpoints, ep)
				}
			}
		}
	}

	return endpoints
}

func extractHTTPRuleBindings(rule *annotations.HttpRule) []EndpointDescriptor {
	if rule == nil {
		return nil
	}
	var out []EndpointDescriptor
	if ep, ok := parseSingleHTTPRule(rule); ok {
		out = append(out, ep)
	}
	for _, b := range rule.GetAdditionalBindings() {
		if ep, ok := parseSingleHTTPRule(b); ok {
			out = append(out, ep)
		}
	}
	return out
}

func parseSingleHTTPRule(rule *annotations.HttpRule) (EndpointDescriptor, bool) {
	if rule == nil {
		return EndpointDescriptor{}, false
	}
	switch p := rule.GetPattern().(type) {
	case *annotations.HttpRule_Get:
		return EndpointDescriptor{Method: "GET", Path: p.Get}, p.Get != ""
	case *annotations.HttpRule_Post:
		return EndpointDescriptor{Method: "POST", Path: p.Post}, p.Post != ""
	case *annotations.HttpRule_Put:
		return EndpointDescriptor{Method: "PUT", Path: p.Put}, p.Put != ""
	case *annotations.HttpRule_Delete:
		return EndpointDescriptor{Method: "DELETE", Path: p.Delete}, p.Delete != ""
	case *annotations.HttpRule_Patch:
		return EndpointDescriptor{Method: "PATCH", Path: p.Patch}, p.Patch != ""
	case *annotations.HttpRule_Custom:
		if p.Custom != nil && p.Custom.GetPath() != "" {
			kind := strings.ToUpper(strings.TrimSpace(p.Custom.GetKind()))
			if kind == "" {
				kind = "CUSTOM"
			}
			return EndpointDescriptor{Method: kind, Path: p.Custom.GetPath()}, true
		}
	}
	return EndpointDescriptor{}, false
}

// DecorateEndpoints returns a new copy of endpoints with default middleware attached to specified routes.
// The key in decorators can be "METHOD:PATH" (e.g. "GET:/api/v1/auth/github/callback") or just "PATH".
func DecorateEndpoints(endpoints []EndpointDescriptor, decorators map[string][]middleware.MiddlewareItem) []EndpointDescriptor {
	result := make([]EndpointDescriptor, len(endpoints))
	for i, ep := range endpoints {
		key := ep.Method + ":" + ep.Path
		mw, exists := decorators[key]
		if !exists {
			mw, exists = decorators[ep.Path]
		}
		if exists {
			ep.DefaultMiddleware = append(ep.DefaultMiddleware, mw...)
		}
		result[i] = ep
	}
	return result
}

// DefaultAuthEndpoints dynamically discovers all REST routes declared in auth.proto via reflection,
// decorated with required endpoint-level middleware (e.g. github_app_callback).
var DefaultAuthEndpoints = DecorateEndpoints(
	ExtractEndpointsFromFileDescriptor(authv1.File_auth_v1_auth_proto, "AuthService"),
	map[string][]middleware.MiddlewareItem{
		"GET:/api/v1/auth/github/callback": {
			{Name: "github_app_callback"},
		},
	},
)

// DefaultGitHubEndpoints dynamically discovers all REST routes declared in github.proto via reflection,
// plus the supplemental raw webhook handler endpoint.
var DefaultGitHubEndpoints = append(
	ExtractEndpointsFromFileDescriptor(githubv1.File_github_v1_github_proto, "GitHubService"),
	EndpointDescriptor{Method: "POST", Path: "/api/v1/github/webhooks"},
)

// DefaultServiceManagerEndpoints dynamically discovers all REST routes declared in servicemanager.proto via reflection.
var DefaultServiceManagerEndpoints = ExtractEndpointsFromFileDescriptor(servicemanagerv1.File_servicemanager_v1_servicemanager_proto, "ServiceManagerService")

// DefaultSecretsEndpoints dynamically discovers all write-only REST routes declared in secrets.proto via reflection.
// Note: SecretsInternalService (ResolveProjectSecrets) is intentionally excluded and never exposed on the gateway perimeter.
var DefaultSecretsEndpoints = ExtractEndpointsFromFileDescriptor(secretsv1.File_secrets_v1_secrets_proto, "SecretsService")

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
			return authv1.RegisterAuthServiceHandlerClient(ctx, mux, client)
		},
		Endpoints: DefaultAuthEndpoints,
	})
	_ = reg.RegisterService("github", ServiceRegistration{
		Registrar: func(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
			client := githubv1.NewGitHubServiceClient(conn)
			if err := githubv1.RegisterGitHubServiceHandlerClient(ctx, mux, client); err != nil {
				return err
			}
			// Mount custom raw-body handler for GitHub webhooks so exact payload bytes are preserved for HMAC-SHA256 verification.
			maxBytes := resolveWebhookMaxBytes()
			return mux.HandlePath("POST", "/api/v1/github/webhooks", func(w http.ResponseWriter, r *http.Request, _ map[string]string) {
				body, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
				if err != nil || int64(len(body)) > maxBytes {
					middleware.WriteError(w, r, http.StatusRequestEntityTooLarge, "payload too large", "PAYLOAD_TOO_LARGE")
					return
				}
				resp, err := client.HandleGitHubWebhook(r.Context(), &githubv1.HandleGitHubWebhookRequest{
					Payload:         body,
					SignatureHeader: r.Header.Get("X-Hub-Signature-256"),
					EventType:       r.Header.Get("X-GitHub-Event"),
					DeliveryId:      r.Header.Get("X-GitHub-Delivery"),
				})
				if err != nil {
					switch status.Code(err) {
					case codes.Unauthenticated:
						middleware.WriteError(w, r, http.StatusUnauthorized, "invalid signature", "UNAUTHORIZED")
					case codes.InvalidArgument:
						middleware.WriteError(w, r, http.StatusBadRequest, "invalid payload", "INVALID_ARGUMENT")
					case codes.ResourceExhausted:
						middleware.WriteError(w, r, http.StatusRequestEntityTooLarge, "payload too large", "PAYLOAD_TOO_LARGE")
					default:
						middleware.WriteError(w, r, http.StatusInternalServerError, "internal processing error", "INTERNAL_ERROR")
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
		Endpoints: DefaultGitHubEndpoints,
	})
	_ = reg.RegisterService("servicemanager", ServiceRegistration{
		Registrar: func(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
			client := servicemanagerv1.NewServiceManagerServiceClient(conn)
			return servicemanagerv1.RegisterServiceManagerServiceHandlerClient(ctx, mux, client)
		},
		Endpoints: DefaultServiceManagerEndpoints,
	})
	_ = reg.RegisterService("secrets", ServiceRegistration{
		Registrar: func(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
			client := secretsv1.NewSecretsServiceClient(conn)
			return secretsv1.RegisterSecretsServiceHandlerClient(ctx, mux, client)
		},
		Endpoints: DefaultSecretsEndpoints,
	})
	return reg
}
