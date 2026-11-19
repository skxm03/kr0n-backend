package handlers

import (
	"context"
	"log"
	"net"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
)

// getMetadata retrieves incoming or outgoing metadata from ctx.
func getMetadata(ctx context.Context) (metadata.MD, bool) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		return md, true
	}
	return metadata.FromOutgoingContext(ctx)
}

// metadataValue returns the first non-empty value for key from gRPC metadata.
func metadataValue(ctx context.Context, key string) string {
	md, ok := getMetadata(ctx)
	if !ok {
		return ""
	}
	vals := md.Get(key)
	if len(vals) == 0 {
		return ""
	}
	return strings.TrimSpace(vals[0])
}

// extractClientIP retrieves client IP from metadata or fallback.
func extractClientIP(ctx context.Context, fallback string) *net.IP {
	raw := fallback
	if mdIP := metadataValue(ctx, "x-client-ip"); mdIP != "" {
		raw = mdIP
	}
	if raw == "" {
		return nil
	}
	if parsed := net.ParseIP(strings.TrimSpace(raw)); parsed != nil {
		return &parsed
	}
	return nil
}

// extractUserAgent retrieves user agent from metadata or fallback.
func extractUserAgent(ctx context.Context, fallback string) *string {
	ua := fallback
	if mdUA := metadataValue(ctx, "x-user-agent"); mdUA != "" {
		ua = mdUA
	}
	if ua == "" {
		return nil
	}
	return &ua
}

// ParseCallerPrincipal resolves the authenticated caller principal strictly from the request's CallerPrincipal passport.
// Caller identity must never be extracted from insecure gRPC transport metadata headers.
func (s *Server) ParseCallerPrincipal(ctx context.Context, c *authv1.CallerPrincipal) (repository.Principal, error) {
	if s.serviceAuth.Enabled && !IsTrustedService(ctx) {
		return repository.Principal{}, status.Error(codes.Unauthenticated, "caller principal rejected: untrusted service boundary")
	}

	if c == nil || strings.TrimSpace(c.GetUserId()) == "" {
		return repository.Principal{}, status.Error(codes.Unauthenticated, "authentication required: missing caller passport")
	}

	uid, err := uuid.Parse(strings.TrimSpace(c.GetUserId()))
	if err != nil {
		return repository.Principal{}, status.Error(codes.InvalidArgument, "invalid caller user_id")
	}

	p := repository.Principal{
		UserID:           uid,
		Kind:             c.GetKind(),
		TokenPermissions: c.GetTokenPermissions(),
	}
	if rawOrg := strings.TrimSpace(c.GetTokenOrgId()); rawOrg != "" {
		if oid, err := uuid.Parse(rawOrg); err == nil {
			p.TokenOrgID = &oid
		}
	}
	if rawSess := strings.TrimSpace(c.GetSessionId()); rawSess != "" {
		if sid, err := uuid.Parse(rawSess); err == nil {
			p.SessionID = &sid
		}
	}

	return p, nil
}

func (s *Server) parseCallerPrincipal(ctx context.Context, c *authv1.CallerPrincipal) (repository.Principal, error) {
	return s.ParseCallerPrincipal(ctx, c)
}

func actorTypeFromPrincipal(p repository.Principal) string {
	if p.Kind == repository.ActorTypeAPIToken {
		return repository.ActorTypeAPIToken
	}
	return repository.ActorTypeUser
}

// recordAudit logs an audit event if auditService is configured.
func (s *Server) recordAudit(ctx context.Context, ev repository.AuditEvent) {
	if s.auditService == nil {
		return
	}
	if ev.IPAddress == nil {
		ev.IPAddress = extractClientIP(ctx, "")
	}
	if ev.UserAgent == nil {
		ev.UserAgent = extractUserAgent(ctx, "")
	}
	if reqID := metadataValue(ctx, "x-request-id"); reqID != "" {
		if ev.Metadata == nil {
			ev.Metadata = map[string]any{}
		}
		if _, exists := ev.Metadata["request_id"]; !exists {
			ev.Metadata["request_id"] = reqID
		}
	}
	if err := s.auditService.Record(ctx, ev); err != nil {
		log.Printf("audit event write error (%s): %v", ev.Action, err)
	}
}
