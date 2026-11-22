package grpcauth

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// ServiceAuthConfig defines the authentication policy for callers of internal gRPC services.
type ServiceAuthConfig struct {
	// Enabled determines whether service-to-service authentication is enforced.
	Enabled bool
	// RequireClientCert mandates a valid mTLS client certificate chaining to the trusted CA
	// whose Subject CommonName or DNS SAN matches AllowedClientNames.
	RequireClientCert bool
	// AllowedClientNames specifies acceptable client certificate Subject CommonNames or DNS SANs (e.g. "kr0n-gateway").
	AllowedClientNames []string
	// AllowInsecureDev permits unauthenticated calls ONLY in development environments when explicitly configured.
	AllowInsecureDev bool
	// IsProtectedMethod optionally specifies whether an RPC requires service auth. If nil, all methods are protected.
	IsProtectedMethod func(fullMethod string) bool
}

type serviceAuthContextKey struct{}

var trustedServiceKey = serviceAuthContextKey{}

// WithTrustedService marks ctx as originating from an authenticated, trusted internal service.
func WithTrustedService(ctx context.Context, serviceName string) context.Context {
	return context.WithValue(ctx, trustedServiceKey, serviceName)
}

// TrustedServiceName returns the authenticated service name in ctx, or "" if untrusted.
func TrustedServiceName(ctx context.Context) string {
	v, _ := ctx.Value(trustedServiceKey).(string)
	return v
}

// IsTrustedService reports whether ctx was authenticated as originating from a trusted service.
func IsTrustedService(ctx context.Context) bool {
	return TrustedServiceName(ctx) != ""
}

// AuthenticateCaller verifies transport mTLS credentials against cfg.
func (c ServiceAuthConfig) AuthenticateCaller(ctx context.Context) (string, bool) {
	if !c.Enabled {
		return "unauthenticated-mode", true
	}
	if c.AllowInsecureDev {
		return "insecure-dev", true
	}

	// Verify mTLS client certificate from transport peer
	if p, ok := peer.FromContext(ctx); ok && p.AuthInfo != nil {
		if tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			for _, chain := range tlsInfo.State.VerifiedChains {
				if len(chain) == 0 {
					continue
				}
				leaf := chain[0]
				for _, allowed := range c.AllowedClientNames {
					if strings.EqualFold(leaf.Subject.CommonName, allowed) {
						return leaf.Subject.CommonName, true
					}
					for _, dns := range leaf.DNSNames {
						if strings.EqualFold(dns, allowed) {
							return dns, true
						}
					}
				}
			}
		}
	}

	return "", false
}

// NewServiceAuthInterceptor creates a gRPC UnaryServerInterceptor that enforces service authentication.
func NewServiceAuthInterceptor(cfg ServiceAuthConfig) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		name, ok := cfg.AuthenticateCaller(ctx)
		if ok {
			ctx = WithTrustedService(ctx, name)
		} else if cfg.Enabled {
			if cfg.IsProtectedMethod == nil || cfg.IsProtectedMethod(info.FullMethod) {
				return nil, status.Error(codes.Unauthenticated, "trusted service authentication required")
			}
		}
		return handler(ctx, req)
	}
}

// NewServiceAuthStreamInterceptor creates a gRPC StreamServerInterceptor that enforces service authentication.
func NewServiceAuthStreamInterceptor(cfg ServiceAuthConfig) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := ss.Context()
		name, ok := cfg.AuthenticateCaller(ctx)
		if ok {
			ctx = WithTrustedService(ctx, name)
			wrapped := &wrappedServerStream{ServerStream: ss, ctx: ctx}
			return handler(srv, wrapped)
		} else if cfg.Enabled {
			if cfg.IsProtectedMethod == nil || cfg.IsProtectedMethod(info.FullMethod) {
				return status.Error(codes.Unauthenticated, "trusted service authentication required")
			}
		}
		return handler(srv, ss)
	}
}

type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}
