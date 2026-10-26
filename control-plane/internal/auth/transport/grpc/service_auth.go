package grpc

import (
	"context"
	"crypto/subtle"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// ServiceAuthConfig defines the authentication and authorization policy for callers of the Auth gRPC service.
type ServiceAuthConfig struct {
	// Enabled determines whether service-to-service authentication is enforced.
	Enabled bool
	// RequireClientCert mandates a valid mTLS client certificate chaining to the trusted CA
	// whose Subject CommonName or DNS SAN matches AllowedClientNames.
	// When true, requests without a valid allowlisted client certificate fail immediately
	// and cannot fall back to a service token. Mandatory in production.
	RequireClientCert bool
	// RequireServiceToken requires the shared service token in metadata in addition to mTLS (defense-in-depth).
	RequireServiceToken bool
	// AllowedClientNames specifies acceptable client certificate Subject CommonNames or DNS SANs (e.g. "kr0n-gateway").
	AllowedClientNames []string
	// ServiceToken specifies an optional shared service secret passed in "x-service-token" or "authorization" metadata.
	ServiceToken string
	// AllowInsecureDev permits unauthenticated calls ONLY in development environments when explicitly configured.
	AllowInsecureDev bool
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

// AuthenticateCaller verifies transport mTLS credentials or service token metadata against cfg.
func (c ServiceAuthConfig) AuthenticateCaller(ctx context.Context) (string, bool) {
	if !c.Enabled {
		return "unauthenticated-mode", true
	}
	if c.AllowInsecureDev {
		return "insecure-dev", true
	}

	var authenticatedClient string
	var certVerified bool

	// 1. Verify mTLS client certificate from transport peer
	if p, ok := peer.FromContext(ctx); ok && p.AuthInfo != nil {
		if tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			for _, chain := range tlsInfo.State.VerifiedChains {
				if len(chain) == 0 {
					continue
				}
				leaf := chain[0]
				for _, allowed := range c.AllowedClientNames {
					if strings.EqualFold(leaf.Subject.CommonName, allowed) {
						authenticatedClient = leaf.Subject.CommonName
						certVerified = true
						break
					}
					for _, dns := range leaf.DNSNames {
						if strings.EqualFold(dns, allowed) {
							authenticatedClient = dns
							certVerified = true
							break
						}
					}
					if certVerified {
						break
					}
				}
				if certVerified {
					break
				}
			}
		}
	}

	// In mandatory mTLS mode (production), client certificate verification MUST succeed
	// and the client identity MUST be on the allowlist. A service token CANNOT compensate
	// for a missing, invalid, or unallowlisted client certificate.
	if c.RequireClientCert && !certVerified {
		return "", false
	}

	// 2. If a service token is required (defense-in-depth), verify it in addition to mTLS.
	if c.RequireServiceToken {
		if !c.verifyServiceToken(ctx) {
			return "", false
		}
	}

	if certVerified {
		return authenticatedClient, true
	}

	// 3. Fallback to service token ONLY when client certificates are NOT required (e.g. local dev mode without mTLS).
	if !c.RequireClientCert && c.ServiceToken != "" && c.verifyServiceToken(ctx) {
		return "service-token", true
	}

	return "", false
}

func (c ServiceAuthConfig) verifyServiceToken(ctx context.Context) bool {
	if c.ServiceToken == "" {
		return false
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	for _, tok := range md.Get("x-service-token") {
		if subtle.ConstantTimeCompare([]byte(tok), []byte(c.ServiceToken)) == 1 {
			return true
		}
	}
	for _, auth := range md.Get("authorization") {
		if strings.HasPrefix(auth, "Bearer ") {
			tok := strings.TrimPrefix(auth, "Bearer ")
			if subtle.ConstantTimeCompare([]byte(tok), []byte(c.ServiceToken)) == 1 {
				return true
			}
		}
	}
	return false
}

// IsProtectedMethod reports whether fullMethod requires an authenticated trusted service.
func IsProtectedMethod(fullMethod string) bool {
	// Public discovery endpoints like GetJWKS are exempt from service-to-service auth;
	// all RPCs accepting user identity, credentials, or caller principals require service auth.
	return !strings.HasSuffix(fullMethod, "/GetJWKS")
}

// NewServiceAuthInterceptor creates a gRPC UnaryServerInterceptor that enforces service authentication.
func NewServiceAuthInterceptor(cfg ServiceAuthConfig) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		name, ok := cfg.AuthenticateCaller(ctx)
		if ok {
			ctx = WithTrustedService(ctx, name)
		} else if cfg.Enabled && IsProtectedMethod(info.FullMethod) {
			return nil, status.Error(codes.Unauthenticated, "trusted service authentication required")
		}
		return handler(ctx, req)
	}
}
