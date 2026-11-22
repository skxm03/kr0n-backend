package grpcauth_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/skxm03/kr0n-backend/control-plane/pkg/grpcauth"
)

func TestServiceAuth_AuthenticateCaller(t *testing.T) {
	cfg := grpcauth.ServiceAuthConfig{
		Enabled:            true,
		RequireClientCert:  true,
		AllowedClientNames: []string{"kr0n-gateway", "gateway.internal.kr0n"},
	}

	// 1. Untrusted caller (no peer info) -> MUST FAIL
	name, ok := cfg.AuthenticateCaller(context.Background())
	if ok || name != "" {
		t.Fatalf("expected untrusted caller without client cert to fail, got name=%q ok=%v", name, ok)
	}

	// 2. Peer with untrusted cert CN -> MUST FAIL
	untrustedPeer := &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{
					{
						{
							Subject: pkix.Name{CommonName: "untrusted-attacker"},
						},
					},
				},
			},
		},
	}
	ctxUntrusted := peer.NewContext(context.Background(), untrustedPeer)
	name, ok = cfg.AuthenticateCaller(ctxUntrusted)
	if ok || name != "" {
		t.Fatalf("expected untrusted cert to fail, got name=%q ok=%v", name, ok)
	}

	// 3. Peer with trusted cert CN -> SUCCEEDS
	trustedPeer := &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{
					{
						{
							Subject: pkix.Name{CommonName: "kr0n-gateway"},
						},
					},
				},
			},
		},
	}
	ctxTrusted := peer.NewContext(context.Background(), trustedPeer)
	name, ok = cfg.AuthenticateCaller(ctxTrusted)
	if !ok || name != "kr0n-gateway" {
		t.Fatalf("expected trusted cert to succeed, got name=%q ok=%v", name, ok)
	}

	// 4. Peer with trusted DNS SAN -> SUCCEEDS
	trustedDNSPeer := &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{
					{
						{
							Subject:  pkix.Name{CommonName: "some-pod"},
							DNSNames: []string{"gateway.internal.kr0n"},
						},
					},
				},
			},
		},
	}
	ctxDNS := peer.NewContext(context.Background(), trustedDNSPeer)
	name, ok = cfg.AuthenticateCaller(ctxDNS)
	if !ok || name != "gateway.internal.kr0n" {
		t.Fatalf("expected trusted DNS SAN to succeed, got name=%q ok=%v", name, ok)
	}

	// 5. Insecure dev mode -> SUCCEEDS
	devCfg := grpcauth.ServiceAuthConfig{
		Enabled:          true,
		AllowInsecureDev: true,
	}
	name, ok = devCfg.AuthenticateCaller(context.Background())
	if !ok || name != "insecure-dev" {
		t.Fatalf("expected insecure-dev to succeed, got name=%q ok=%v", name, ok)
	}

	// 6. Disabled mode -> SUCCEEDS
	disabledCfg := grpcauth.ServiceAuthConfig{
		Enabled: false,
	}
	name, ok = disabledCfg.AuthenticateCaller(context.Background())
	if !ok || name != "unauthenticated-mode" {
		t.Fatalf("expected unauthenticated-mode to succeed, got name=%q ok=%v", name, ok)
	}
}

func TestServiceAuthInterceptor(t *testing.T) {
	cfg := grpcauth.ServiceAuthConfig{
		Enabled:            true,
		RequireClientCert:  true,
		AllowedClientNames: []string{"kr0n-gateway"},
		IsProtectedMethod: func(fullMethod string) bool {
			return fullMethod != "/public/HealthCheck"
		},
	}

	interceptor := grpcauth.NewServiceAuthInterceptor(cfg)

	// Call protected method without credentials -> Unauthenticated error
	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/secrets.v1.SecretsService/ResolveProjectSecrets"}, func(ctx context.Context, req any) (any, error) {
		return "ok", nil
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected codes.Unauthenticated, got %v", err)
	}

	// Call exempt method without credentials -> Allowed
	resp, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/public/HealthCheck"}, func(ctx context.Context, req any) (any, error) {
		return "ok", nil
	})
	if err != nil || resp != "ok" {
		t.Fatalf("expected exempt method to succeed, got resp=%v err=%v", resp, err)
	}

	// Call protected method with valid credentials -> Allowed with context marked
	trustedPeer := &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{
					{
						{Subject: pkix.Name{CommonName: "kr0n-gateway"}},
					},
				},
			},
		},
	}
	ctxTrusted := peer.NewContext(context.Background(), trustedPeer)
	resp, err = interceptor(ctxTrusted, nil, &grpc.UnaryServerInfo{FullMethod: "/secrets.v1.SecretsService/ResolveProjectSecrets"}, func(ctx context.Context, req any) (any, error) {
		if !grpcauth.IsTrustedService(ctx) {
			t.Fatal("expected IsTrustedService to be true")
		}
		if grpcauth.TrustedServiceName(ctx) != "kr0n-gateway" {
			t.Fatalf("expected caller name kr0n-gateway, got %q", grpcauth.TrustedServiceName(ctx))
		}
		return "ok", nil
	})
	if err != nil || resp != "ok" {
		t.Fatalf("expected protected method with valid cert to succeed, got resp=%v err=%v", resp, err)
	}
}

func TestExtractPassportMetadata(t *testing.T) {
	// 1. Missing metadata -> false
	if _, ok := grpcauth.ExtractPassportMetadata(context.Background()); ok {
		t.Fatal("expected false for missing metadata")
	}

	// 2. Missing user id -> false
	md := metadata.Pairs("x-passport-kind", "session")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	if _, ok := grpcauth.ExtractPassportMetadata(ctx); ok {
		t.Fatal("expected false for missing user id")
	}

	// 3. Valid full passport metadata -> true and correctly parsed
	uid := uuid.New()
	oid := uuid.New()
	sid := uuid.New()
	md = metadata.Pairs(
		"x-passport-user-id", uid.String(),
		"x-passport-kind", "api_token",
		"x-passport-org-id", oid.String(),
		"x-passport-session-id", sid.String(),
		"x-passport-roles", "project:read, project:write",
	)
	ctx = metadata.NewIncomingContext(context.Background(), md)
	pass, ok := grpcauth.ExtractPassportMetadata(ctx)
	if !ok {
		t.Fatal("expected true for valid passport metadata")
	}
	if pass.UserID != uid {
		t.Fatalf("expected UserID %v, got %v", uid, pass.UserID)
	}
	if pass.Kind != "api_token" {
		t.Fatalf("expected Kind api_token, got %q", pass.Kind)
	}
	if pass.OrgID == nil || *pass.OrgID != oid {
		t.Fatalf("expected OrgID %v, got %v", oid, pass.OrgID)
	}
	if pass.SessionID == nil || *pass.SessionID != sid {
		t.Fatalf("expected SessionID %v, got %v", sid, pass.SessionID)
	}
	if len(pass.Permissions) != 2 || pass.Permissions[0] != "project:read" || pass.Permissions[1] != "project:write" {
		t.Fatalf("expected permissions [project:read, project:write], got %v", pass.Permissions)
	}
}
