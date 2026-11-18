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

// extractUserID extracts and parses the caller user ID from metadata or explicit fallback.
func (s *Server) extractUserID(ctx context.Context, explicit ...string) (uuid.UUID, error) {
	raw := ""
	if len(explicit) > 0 && strings.TrimSpace(explicit[0]) != "" {
		raw = strings.TrimSpace(explicit[0])
	} else {
		raw = metadataValue(ctx, "x-caller-user-id")
	}

	if raw == "" {
		return uuid.Nil, status.Error(codes.Unauthenticated, "authentication required: user_id missing")
	}

	uid, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, status.Error(codes.InvalidArgument, "invalid user_id")
	}
	return uid, nil
}

// extractSessionID extracts and parses the session ID from metadata or explicit fallback.
func (s *Server) extractSessionID(ctx context.Context, explicit ...string) (*uuid.UUID, error) {
	raw := ""
	if len(explicit) > 0 && strings.TrimSpace(explicit[0]) != "" {
		raw = strings.TrimSpace(explicit[0])
	} else {
		raw = metadataValue(ctx, "x-caller-session-id")
	}

	if raw == "" {
		return nil, nil
	}

	uid, err := uuid.Parse(raw)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid session_id")
	}
	return &uid, nil
}

// ParseCallerPrincipal resolves the authenticated caller principal from explicit proto or gRPC metadata.
func (s *Server) ParseCallerPrincipal(ctx context.Context, c *authv1.CallerPrincipal) (repository.Principal, error) {
	if s.serviceAuth.Enabled && !IsTrustedService(ctx) {
		return repository.Principal{}, status.Error(codes.Unauthenticated, "caller principal rejected: untrusted service boundary")
	}

	// 1. Explicit proto principal (internal service-to-service calls like CheckPermission)
	if c != nil && strings.TrimSpace(c.GetUserId()) != "" {
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
		return p, nil
	}

	// 2. Injected gRPC metadata headers (from API Gateway)
	rawUID := metadataValue(ctx, "x-caller-user-id")
	if rawUID == "" {
		return repository.Principal{}, status.Error(codes.Unauthenticated, "authentication required")
	}

	uid, err := uuid.Parse(rawUID)
	if err != nil {
		return repository.Principal{}, status.Error(codes.InvalidArgument, "invalid caller user_id in metadata")
	}

	p := repository.Principal{
		UserID: uid,
		Kind:   metadataValue(ctx, "x-caller-kind"),
	}

	if rawOrg := metadataValue(ctx, "x-caller-token-org-id"); rawOrg != "" {
		if oid, err := uuid.Parse(rawOrg); err == nil {
			p.TokenOrgID = &oid
		}
	}

	if md, ok := getMetadata(ctx); ok {
		for _, perm := range md.Get("x-caller-token-permissions") {
			for _, part := range strings.Split(perm, ",") {
				if trimmed := strings.TrimSpace(part); trimmed != "" {
					p.TokenPermissions = append(p.TokenPermissions, trimmed)
				}
			}
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
