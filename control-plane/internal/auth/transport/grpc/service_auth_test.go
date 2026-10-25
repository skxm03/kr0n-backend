package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/jwtkeys"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/user"
)

func TestServiceAuth_ClientCertAuthentication(t *testing.T) {
	cfg := ServiceAuthConfig{
		Enabled:            true,
		AllowedClientNames: []string{"kr0n-gateway", "gateway.internal.kr0n"},
		ServiceToken:       "secret-service-token-123",
	}

	// 1. Untrusted caller (no peer info)
	name, ok := cfg.AuthenticateCaller(context.Background())
	if ok || name != "" {
		t.Fatalf("expected untrusted caller, got name=%q ok=%v", name, ok)
	}

	// 2. Peer with untrusted cert CN
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

	// 3. Peer with trusted cert CN
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

	// 4. Peer with trusted DNS SAN
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
}

func TestServiceAuth_ServiceTokenAuthentication(t *testing.T) {
	cfg := ServiceAuthConfig{
		Enabled:      true,
		ServiceToken: "kr0n-super-secret-service-token",
	}

	// 1. Missing metadata
	_, ok := cfg.AuthenticateCaller(context.Background())
	if ok {
		t.Fatal("expected failure with missing metadata")
	}

	// 2. Wrong x-service-token
	ctxBad := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-service-token", "wrong-token"))
	_, ok = cfg.AuthenticateCaller(ctxBad)
	if ok {
		t.Fatal("expected failure with wrong token")
	}

	// 3. Valid x-service-token
	ctxGood := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-service-token", "kr0n-super-secret-service-token"))
	name, ok := cfg.AuthenticateCaller(ctxGood)
	if !ok || name != "service-token" {
		t.Fatalf("expected success with x-service-token, got name=%q ok=%v", name, ok)
	}

	// 4. Valid Bearer authorization header
	ctxBearer := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer kr0n-super-secret-service-token"))
	name, ok = cfg.AuthenticateCaller(ctxBearer)
	if !ok || name != "service-token" {
		t.Fatalf("expected success with Bearer authorization, got name=%q ok=%v", name, ok)
	}
}

func TestServiceAuth_SpoofedPrincipalRejection(t *testing.T) {
	s := &Server{
		serviceAuth: ServiceAuthConfig{
			Enabled: true,
		},
	}

	fakeCaller := &authv1.CallerPrincipal{
		UserId:           uuid.New().String(),
		Kind:             "user",
		TokenPermissions: []string{"org:admin"},
	}

	// 1. Untrusted context calling parseCallerPrincipal
	_, err := s.parseCallerPrincipal(context.Background(), fakeCaller)
	if err == nil {
		t.Fatal("expected untrusted caller to be rejected, got nil")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}

	// 2. Trusted context calling parseCallerPrincipal
	trustedCtx := WithTrustedService(context.Background(), "kr0n-gateway")
	p, err := s.parseCallerPrincipal(trustedCtx, fakeCaller)
	if err != nil {
		t.Fatalf("expected trusted caller to succeed, got %v", err)
	}
	if p.UserID.String() != fakeCaller.GetUserId() {
		t.Fatalf("expected user ID %s, got %s", fakeCaller.GetUserId(), p.UserID.String())
	}
}

func TestServiceAuth_Interceptor_E2E(t *testing.T) {
	const validToken = "test-service-token-valid"
	svcAuthConfig := ServiceAuthConfig{
		Enabled:      true,
		ServiceToken: validToken,
	}

	lis := bufconn.Listen(1024 * 1024)
	t.Cleanup(func() { _ = lis.Close() })

	mockReg := &mockRegistrationService{
		registerFunc: func(ctx context.Context, params user.RegisterParams) (*user.User, error) {
			return &user.User{ID: uuid.New(), Email: params.Email}, nil
		},
	}

	serverHandler := NewServer(mockReg, nil,
		WithJWKS(jwtkeys.JWK{Kty: "RSA", Kid: "test-kid", Use: "sig", Alg: "RS256"}),
		WithServiceAuthConfig(svcAuthConfig),
	)

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(NewServiceAuthInterceptor(svcAuthConfig)),
	)
	authv1.RegisterAuthServiceServer(grpcServer, serverHandler)

	go func() {
		_ = grpcServer.Serve(lis)
	}()
	t.Cleanup(func() { grpcServer.Stop() })

	conn, err := grpc.DialContext(context.Background(), "bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to dial bufconn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	client := authv1.NewAuthServiceClient(conn)

	// 1. Calling GetJWKS (public endpoint) without credentials MUST SUCCEED
	jwksResp, err := client.GetJWKS(context.Background(), &authv1.GetJWKSRequest{})
	if err != nil {
		t.Fatalf("expected GetJWKS to succeed without service auth, got %v", err)
	}
	if len(jwksResp.GetKeys()) == 0 {
		t.Fatal("expected non-empty JWKS response")
	}

	// 2. Calling Register (protected endpoint) without credentials MUST FAIL with Unauthenticated
	_, err = client.Register(context.Background(), &authv1.RegisterRequest{
		Email:       "alice@kr0n.dev",
		Password:    "ValidPassword123!",
		DisplayName: "Alice",
	})
	if err == nil {
		t.Fatal("expected Register without service auth to fail, got nil")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}

	// 3. Calling Register with WRONG service token MUST FAIL
	badCtx := metadata.AppendToOutgoingContext(context.Background(), "x-service-token", "wrong-token")
	_, err = client.Register(badCtx, &authv1.RegisterRequest{
		Email:       "alice@kr0n.dev",
		Password:    "ValidPassword123!",
		DisplayName: "Alice",
	})
	if err == nil {
		t.Fatal("expected Register with wrong token to fail, got nil")
	}
	st, ok = status.FromError(err)
	if !ok || st.Code() != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated on wrong token, got %v", err)
	}

	// 4. Calling Register with VALID service token MUST SUCCEED
	goodCtx := metadata.AppendToOutgoingContext(context.Background(), "x-service-token", validToken)
	regResp, err := client.Register(goodCtx, &authv1.RegisterRequest{
		Email:       "alice@kr0n.dev",
		Password:    "ValidPassword123!",
		DisplayName: "Alice",
	})
	if err != nil {
		t.Fatalf("expected Register with valid service token to succeed, got %v", err)
	}
	if regResp.GetEmail() != "alice@kr0n.dev" {
		t.Fatalf("expected email alice@kr0n.dev, got %s", regResp.GetEmail())
	}
}
