package handlers

import (
	"strings"

	"google.golang.org/grpc"

	"github.com/skxm03/kr0n-backend/control-plane/pkg/grpcauth"
)

// ServiceAuthConfig defines the authentication policy for callers of the Auth gRPC service.
type ServiceAuthConfig = grpcauth.ServiceAuthConfig

var (
	WithTrustedService = grpcauth.WithTrustedService
	TrustedServiceName = grpcauth.TrustedServiceName
	IsTrustedService   = grpcauth.IsTrustedService
)

// IsProtectedMethod reports whether fullMethod requires an authenticated trusted service.
func IsProtectedMethod(fullMethod string) bool {
	// Public discovery endpoints like GetJWKS are exempt from service-to-service auth;
	// all RPCs accepting user identity, credentials, or caller principals require service auth.
	return !strings.HasSuffix(fullMethod, "/GetJWKS")
}

// NewServiceAuthInterceptor creates a gRPC UnaryServerInterceptor that enforces service authentication.
func NewServiceAuthInterceptor(cfg ServiceAuthConfig) grpc.UnaryServerInterceptor {
	if cfg.IsProtectedMethod == nil {
		cfg.IsProtectedMethod = IsProtectedMethod
	}
	return grpcauth.NewServiceAuthInterceptor(cfg)
}
