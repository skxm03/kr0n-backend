package grpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

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
		Enabled:             true,
		RequireClientCert:   true,
		AllowedClientNames:  []string{"kr0n-gateway", "gateway.internal.kr0n"},
		ServiceToken:        "secret-service-token-123",
		RequireServiceToken: false,
	}

	// 1. Untrusted caller (no peer info, but supplies service token) -> MUST FAIL because RequireClientCert=true
	ctxWithToken := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-service-token", "secret-service-token-123"))
	name, ok := cfg.AuthenticateCaller(ctxWithToken)
	if ok || name != "" {
		t.Fatalf("expected untrusted caller without client cert to fail even with valid service token, got name=%q ok=%v", name, ok)
	}

	// 2. Peer with untrusted cert CN (even with valid service token) -> MUST FAIL
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
	ctxUntrusted := peer.NewContext(ctxWithToken, untrustedPeer)
	name, ok = cfg.AuthenticateCaller(ctxUntrusted)
	if ok || name != "" {
		t.Fatalf("expected untrusted cert to fail even with valid service token, got name=%q ok=%v", name, ok)
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

	// 5. RequireServiceToken=true (defense-in-depth mode):
	// mTLS cert succeeds, but missing service token -> MUST FAIL
	cfgDual := ServiceAuthConfig{
		Enabled:             true,
		RequireClientCert:   true,
		RequireServiceToken: true,
		AllowedClientNames:  []string{"kr0n-gateway"},
		ServiceToken:        "dual-token-456",
	}
	name, ok = cfgDual.AuthenticateCaller(ctxTrusted)
	if ok || name != "" {
		t.Fatalf("expected failure when service token is missing in dual mode, got name=%q ok=%v", name, ok)
	}

	// mTLS cert succeeds, AND valid service token supplied -> SUCCEEDS
	ctxDualGood := metadata.NewIncomingContext(ctxTrusted, metadata.Pairs("x-service-token", "dual-token-456"))
	name, ok = cfgDual.AuthenticateCaller(ctxDualGood)
	if !ok || name != "kr0n-gateway" {
		t.Fatalf("expected success with cert + token in dual mode, got name=%q ok=%v", name, ok)
	}
}

func TestServiceAuth_ServiceTokenAuthentication(t *testing.T) {
	// Dev mode with RequireClientCert=false: service token authentication is permitted
	cfg := ServiceAuthConfig{
		Enabled:           true,
		RequireClientCert: false,
		ServiceToken:      "kr0n-super-secret-service-token",
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
		Enabled:           true,
		RequireClientCert: false, // dev token mode
		ServiceToken:      validToken,
	}

	lis := bufconn.Listen(1024 * 1024)
	t.Cleanup(func() { _ = lis.Close() })

	mockReg := &mockRegistrationService{
		registerFunc: func(ctx context.Context, params user.RegisterParams) (*user.User, error) {
			return &user.User{ID: uuid.New(), Email: params.Email}, nil
		},
	}

	serverHandler := NewServer(mockReg, nil,
		WithJWKS(jwtkeys.JWK{Kty: "OKP", Kid: "test-kid", Use: "sig", Alg: "EdDSA", Crv: "Ed25519"}),
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

func generateTestPKI(t *testing.T) (
	rootCAPool *x509.CertPool,
	untrustedCAPool *x509.CertPool,
	serverCert tls.Certificate,
	validClientCert tls.Certificate,
	unallowlistedClientCert tls.Certificate,
	untrustedClientCert tls.Certificate,
	expiredClientCert tls.Certificate,
) {
	t.Helper()

	// 1. Root CA
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "kr0n-test-root-ca"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create root CA cert: %v", err)
	}
	rootCA, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root CA cert: %v", err)
	}
	rootCAPool = x509.NewCertPool()
	rootCAPool.AddCert(rootCA)

	// 2. Untrusted CA
	untrustedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate untrusted key: %v", err)
	}
	untrustedTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "untrusted-attacker-ca"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	untrustedDER, err := x509.CreateCertificate(rand.Reader, untrustedTmpl, untrustedTmpl, &untrustedKey.PublicKey, untrustedKey)
	if err != nil {
		t.Fatalf("create untrusted CA cert: %v", err)
	}
	untrustedCA, err := x509.ParseCertificate(untrustedDER)
	if err != nil {
		t.Fatalf("parse untrusted CA cert: %v", err)
	}
	untrustedCAPool = x509.NewCertPool()
	untrustedCAPool.AddCert(untrustedCA)

	signLeaf := func(ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, dnsNames []string, isServer bool, notBefore, notAfter time.Time) tls.Certificate {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate leaf key: %v", err)
		}
		extUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		if isServer {
			extUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: cn},
			DNSNames:     dnsNames,
			NotBefore:    notBefore,
			NotAfter:     notAfter,
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  extUsage,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &priv.PublicKey, caKey)
		if err != nil {
			t.Fatalf("create leaf cert %q: %v", cn, err)
		}
		return tls.Certificate{
			Certificate: [][]byte{der},
			PrivateKey:  priv,
		}
	}

	now := time.Now()
	serverCert = signLeaf(rootCA, rootKey, "auth.internal", []string{"auth.internal", "localhost"}, true, now.Add(-1*time.Hour), now.Add(24*time.Hour))
	validClientCert = signLeaf(rootCA, rootKey, "kr0n-gateway", []string{"kr0n-gateway"}, false, now.Add(-1*time.Hour), now.Add(24*time.Hour))
	unallowlistedClientCert = signLeaf(rootCA, rootKey, "rogue-service", []string{"rogue-service"}, false, now.Add(-1*time.Hour), now.Add(24*time.Hour))
	untrustedClientCert = signLeaf(untrustedCA, untrustedKey, "kr0n-gateway", []string{"kr0n-gateway"}, false, now.Add(-1*time.Hour), now.Add(24*time.Hour))
	expiredClientCert = signLeaf(rootCA, rootKey, "kr0n-gateway", []string{"kr0n-gateway"}, false, now.Add(-5*time.Hour), now.Add(-1*time.Hour))

	return
}

func TestServiceAuth_RealTransport_mTLS(t *testing.T) {
	rootCAPool, untrustedCAPool, serverCert, validClientCert, unallowlistedClientCert, untrustedClientCert, expiredClientCert := generateTestPKI(t)

	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    rootCAPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	serviceAuthConfig := ServiceAuthConfig{
		Enabled:             true,
		RequireClientCert:   true,
		RequireServiceToken: false,
		AllowedClientNames:  []string{"kr0n-gateway"},
		ServiceToken:        "super-secret-token",
	}

	lis := bufconn.Listen(1024 * 1024)
	t.Cleanup(func() { _ = lis.Close() })

	mockReg := &mockRegistrationService{
		registerFunc: func(ctx context.Context, params user.RegisterParams) (*user.User, error) {
			return &user.User{ID: uuid.New(), Email: params.Email}, nil
		},
	}
	serverHandler := NewServer(mockReg, nil,
		WithJWKS(jwtkeys.JWK{Kty: "OKP", Kid: "test-kid", Use: "sig", Alg: "EdDSA", Crv: "Ed25519"}),
		WithServiceAuthConfig(serviceAuthConfig),
	)

	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(serverTLSConfig)),
		grpc.UnaryInterceptor(NewServiceAuthInterceptor(serviceAuthConfig)),
	)
	authv1.RegisterAuthServiceServer(grpcServer, serverHandler)
	go func() {
		_ = grpcServer.Serve(lis)
	}()
	t.Cleanup(func() { grpcServer.Stop() })

	dialTLS := func(cfg *tls.Config) (*grpc.ClientConn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		var creds credentials.TransportCredentials
		if cfg != nil {
			creds = credentials.NewTLS(cfg)
		} else {
			creds = insecure.NewCredentials()
		}
		return grpc.DialContext(ctx, "bufnet",
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
				return lis.Dial()
			}),
			grpc.WithTransportCredentials(creds),
			grpc.WithBlock(),
		)
	}

	// 1. Trusted client certificate and correct identity -> SUCCEEDS
	t.Run("valid client cert and correct identity succeeds", func(t *testing.T) {
		clientTLS := &tls.Config{
			Certificates: []tls.Certificate{validClientCert},
			RootCAs:      rootCAPool,
			ServerName:   "auth.internal",
			MinVersion:   tls.VersionTLS12,
		}
		conn, err := dialTLS(clientTLS)
		if err != nil {
			t.Fatalf("expected mTLS connection to succeed, got %v", err)
		}
		defer conn.Close()

		client := authv1.NewAuthServiceClient(conn)
		regResp, err := client.Register(context.Background(), &authv1.RegisterRequest{
			Email:       "valid@kr0n.dev",
			Password:    "ValidPassword123!",
			DisplayName: "Valid User",
		})
		if err != nil {
			t.Fatalf("expected Register to succeed over mTLS, got %v", err)
		}
		if regResp.GetEmail() != "valid@kr0n.dev" {
			t.Fatalf("unexpected email %s", regResp.GetEmail())
		}
	})

	// 2. Client certificate signed by an untrusted CA -> REJECTED at TLS handshake
	t.Run("client certificate signed by untrusted CA is rejected at handshake", func(t *testing.T) {
		clientTLS := &tls.Config{
			Certificates: []tls.Certificate{untrustedClientCert},
			RootCAs:      rootCAPool,
			ServerName:   "auth.internal",
			MinVersion:   tls.VersionTLS12,
		}
		conn, err := dialTLS(clientTLS)
		if err == nil {
			defer conn.Close()
			client := authv1.NewAuthServiceClient(conn)
			_, err = client.Register(context.Background(), &authv1.RegisterRequest{
				Email:       "untrusted@kr0n.dev",
				Password:    "Password123!",
				DisplayName: "Untrusted",
			})
		}
		if err == nil {
			t.Fatal("expected untrusted CA client cert to fail, but succeeded")
		}
	})

	// 3. Missing client certificate -> REJECTED at TLS handshake
	t.Run("missing client certificate is rejected at handshake", func(t *testing.T) {
		clientTLS := &tls.Config{
			RootCAs:    rootCAPool,
			ServerName: "auth.internal",
			MinVersion: tls.VersionTLS12,
		}
		conn, err := dialTLS(clientTLS)
		if err == nil {
			defer conn.Close()
			client := authv1.NewAuthServiceClient(conn)
			_, err = client.Register(context.Background(), &authv1.RegisterRequest{
				Email:       "nocert@kr0n.dev",
				Password:    "Password123!",
				DisplayName: "No Cert",
			})
		}
		if err == nil {
			t.Fatal("expected missing client certificate to fail, but succeeded")
		}
	})

	// 4. Trusted CA but unallowlisted client identity -> REJECTED by service-auth policy
	// AND token fallback CANNOT bypass this rejection!
	t.Run("trusted CA but unallowlisted client identity is rejected", func(t *testing.T) {
		clientTLS := &tls.Config{
			Certificates: []tls.Certificate{unallowlistedClientCert},
			RootCAs:      rootCAPool,
			ServerName:   "auth.internal",
			MinVersion:   tls.VersionTLS12,
		}
		conn, err := dialTLS(clientTLS)
		if err != nil {
			t.Fatalf("expected TLS handshake to succeed (valid CA), got %v", err)
		}
		defer conn.Close()

		client := authv1.NewAuthServiceClient(conn)

		// A: Attempt protected RPC without token -> REJECTED
		_, err = client.Register(context.Background(), &authv1.RegisterRequest{
			Email:       "rogue@kr0n.dev",
			Password:    "Password123!",
			DisplayName: "Rogue",
		})
		if err == nil {
			t.Fatal("expected unallowlisted client identity to be rejected by interceptor")
		}
		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.Unauthenticated {
			t.Fatalf("expected Unauthenticated, got %v", err)
		}

		// B: Attempt protected RPC WITH valid service token -> MUST STILL BE REJECTED!
		// (Proves service token cannot bypass unallowlisted client cert in production)
		ctxWithToken := metadata.AppendToOutgoingContext(context.Background(), "x-service-token", "super-secret-token")
		_, err = client.Register(ctxWithToken, &authv1.RegisterRequest{
			Email:       "rogue@kr0n.dev",
			Password:    "Password123!",
			DisplayName: "Rogue",
		})
		if err == nil {
			t.Fatal("expected service token to NOT bypass unallowlisted client cert in production")
		}
		st, ok = status.FromError(err)
		if !ok || st.Code() != codes.Unauthenticated {
			t.Fatalf("expected Unauthenticated, got %v", err)
		}
	})

	// 5. Expired client certificate -> REJECTED at TLS handshake
	t.Run("expired client certificate is rejected at handshake", func(t *testing.T) {
		clientTLS := &tls.Config{
			Certificates: []tls.Certificate{expiredClientCert},
			RootCAs:      rootCAPool,
			ServerName:   "auth.internal",
			MinVersion:   tls.VersionTLS12,
		}
		conn, err := dialTLS(clientTLS)
		if err == nil {
			defer conn.Close()
			client := authv1.NewAuthServiceClient(conn)
			_, err = client.Register(context.Background(), &authv1.RegisterRequest{
				Email:       "expired@kr0n.dev",
				Password:    "Password123!",
				DisplayName: "Expired",
			})
		}
		if err == nil {
			t.Fatal("expected expired client certificate to fail, but succeeded")
		}
	})

	// 6. Incorrect server certificate or server name -> Gateway connection fails
	t.Run("mismatched server name fails TLS verification", func(t *testing.T) {
		clientTLS := &tls.Config{
			Certificates: []tls.Certificate{validClientCert},
			RootCAs:      rootCAPool,
			ServerName:   "wrong-server-name.kr0n.dev",
			MinVersion:   tls.VersionTLS12,
		}
		conn, err := dialTLS(clientTLS)
		if err == nil {
			defer conn.Close()
			client := authv1.NewAuthServiceClient(conn)
			_, err = client.Register(context.Background(), &authv1.RegisterRequest{
				Email:       "wrongserver@kr0n.dev",
				Password:    "Password123!",
				DisplayName: "Wrong Server",
			})
		}
		if err == nil {
			t.Fatal("expected mismatched server name to fail TLS verification, but succeeded")
		}
	})

	// 7. Gateway client with untrusted root CA -> Gateway connection fails
	t.Run("untrusted server CA fails client TLS verification", func(t *testing.T) {
		clientTLS := &tls.Config{
			Certificates: []tls.Certificate{validClientCert},
			RootCAs:      untrustedCAPool,
			ServerName:   "auth.internal",
			MinVersion:   tls.VersionTLS12,
		}
		conn, err := dialTLS(clientTLS)
		if err == nil {
			defer conn.Close()
			client := authv1.NewAuthServiceClient(conn)
			_, err = client.Register(context.Background(), &authv1.RegisterRequest{
				Email:       "untrustedserver@kr0n.dev",
				Password:    "Password123!",
				DisplayName: "Untrusted Server",
			})
		}
		if err == nil {
			t.Fatal("expected untrusted root CA on client to fail TLS verification, but succeeded")
		}
	})

	// 8. Public GetJWKS remains accessible to any client on the TLS connection
	t.Run("public GetJWKS succeeds even when caller identity is unallowlisted", func(t *testing.T) {
		clientTLS := &tls.Config{
			Certificates: []tls.Certificate{unallowlistedClientCert},
			RootCAs:      rootCAPool,
			ServerName:   "auth.internal",
			MinVersion:   tls.VersionTLS12,
		}
		conn, err := dialTLS(clientTLS)
		if err != nil {
			t.Fatalf("expected TLS handshake to succeed: %v", err)
		}
		defer conn.Close()

		client := authv1.NewAuthServiceClient(conn)
		jwks, err := client.GetJWKS(context.Background(), &authv1.GetJWKSRequest{})
		if err != nil {
			t.Fatalf("expected GetJWKS to succeed, got %v", err)
		}
		if len(jwks.GetKeys()) == 0 {
			t.Fatal("expected non-empty JWKS")
		}
	})
}

func TestServiceAuth_SensitiveRPC_TrustBoundary(t *testing.T) {
	s := &Server{
		serviceAuth: ServiceAuthConfig{
			Enabled:           true,
			RequireClientCert: true,
		},
	}
	untrustedCtx := context.Background()

	// Every sensitive RPC accepting user_id, session_id, or caller principal must reject untrustedCtx
	t.Run("ChangePassword rejects untrusted service caller", func(t *testing.T) {
		_, err := s.ChangePassword(untrustedCtx, &authv1.ChangePasswordRequest{
			UserId:          uuid.New().String(),
			CurrentPassword: "pass",
			NewPassword:     "newpass",
		})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("expected Unauthenticated, got %v", err)
		}
	})

	t.Run("GetMe rejects untrusted service caller", func(t *testing.T) {
		_, err := s.GetMe(untrustedCtx, &authv1.GetMeRequest{UserId: uuid.New().String()})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("expected Unauthenticated, got %v", err)
		}
	})

	t.Run("ListSessions rejects untrusted service caller", func(t *testing.T) {
		_, err := s.ListSessions(untrustedCtx, &authv1.ListSessionsRequest{UserId: uuid.New().String()})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("expected Unauthenticated, got %v", err)
		}
	})

	t.Run("RevokeSession rejects untrusted service caller", func(t *testing.T) {
		_, err := s.RevokeSession(untrustedCtx, &authv1.RevokeSessionRequest{
			UserId:    uuid.New().String(),
			SessionId: uuid.New().String(),
		})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("expected Unauthenticated, got %v", err)
		}
	})

	t.Run("CompleteGitHubOAuth rejects untrusted service caller", func(t *testing.T) {
		_, err := s.CompleteGitHubOAuth(untrustedCtx, &authv1.CompleteGitHubOAuthRequest{
			Code:         "code",
			CodeVerifier: "verifier",
		})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("expected Unauthenticated, got %v", err)
		}
	})

	t.Run("CreateOrganization rejects untrusted service caller", func(t *testing.T) {
		_, err := s.CreateOrganization(untrustedCtx, &authv1.CreateOrganizationRequest{
			UserId: uuid.New().String(),
			Name:   "Acme",
			Slug:   "acme",
		})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("expected Unauthenticated, got %v", err)
		}
	})

	t.Run("ListOrganizations rejects untrusted service caller", func(t *testing.T) {
		_, err := s.ListOrganizations(untrustedCtx, &authv1.ListOrganizationsRequest{
			UserId: uuid.New().String(),
		})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("expected Unauthenticated, got %v", err)
		}
	})

	t.Run("AcceptInvite rejects untrusted service caller", func(t *testing.T) {
		_, err := s.AcceptInvite(untrustedCtx, &authv1.AcceptInviteRequest{
			UserId: uuid.New().String(),
			Token:  "invite-tok",
		})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("expected Unauthenticated, got %v", err)
		}
	})
}

func TestServiceAuth_OrgRPCs_CallerPrincipal_TrustBoundary(t *testing.T) {
	s := &Server{
		serviceAuth: ServiceAuthConfig{
			Enabled:           true,
			RequireClientCert: true,
		},
	}
	untrustedCtx := context.Background()
	dummyCaller := &authv1.CallerPrincipal{
		UserId: uuid.New().String(),
		Kind:   "user",
	}
	orgID := uuid.New().String()

	t.Run("CheckPermission rejects untrusted caller", func(t *testing.T) {
		_, err := s.CheckPermission(untrustedCtx, &authv1.CheckPermissionRequest{Caller: dummyCaller, OrgId: orgID, Permission: "org:read"})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("expected Unauthenticated, got %v", err)
		}
	})

	t.Run("GetOrganization rejects untrusted caller", func(t *testing.T) {
		_, err := s.GetOrganization(untrustedCtx, &authv1.GetOrganizationRequest{Caller: dummyCaller, OrgId: orgID})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("expected Unauthenticated, got %v", err)
		}
	})

	t.Run("UpdateOrganization rejects untrusted caller", func(t *testing.T) {
		_, err := s.UpdateOrganization(untrustedCtx, &authv1.UpdateOrganizationRequest{Caller: dummyCaller, OrgId: orgID, Name: "New Name"})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("expected Unauthenticated, got %v", err)
		}
	})

	t.Run("DeleteOrganization rejects untrusted caller", func(t *testing.T) {
		_, err := s.DeleteOrganization(untrustedCtx, &authv1.DeleteOrganizationRequest{Caller: dummyCaller, OrgId: orgID})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("expected Unauthenticated, got %v", err)
		}
	})

	t.Run("ListMembers rejects untrusted caller", func(t *testing.T) {
		_, err := s.ListMembers(untrustedCtx, &authv1.ListMembersRequest{Caller: dummyCaller, OrgId: orgID})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("expected Unauthenticated, got %v", err)
		}
	})

	t.Run("AddMember rejects untrusted caller", func(t *testing.T) {
		_, err := s.AddMember(untrustedCtx, &authv1.AddMemberRequest{Caller: dummyCaller, OrgId: orgID, Email: "a@b.com", RoleId: "member"})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("expected Unauthenticated, got %v", err)
		}
	})

	t.Run("UpdateMemberRole rejects untrusted caller", func(t *testing.T) {
		_, err := s.UpdateMemberRole(untrustedCtx, &authv1.UpdateMemberRoleRequest{Caller: dummyCaller, OrgId: orgID, TargetUserId: uuid.New().String(), RoleId: "admin"})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("expected Unauthenticated, got %v", err)
		}
	})

	t.Run("RemoveMember rejects untrusted caller", func(t *testing.T) {
		_, err := s.RemoveMember(untrustedCtx, &authv1.RemoveMemberRequest{Caller: dummyCaller, OrgId: orgID, TargetUserId: uuid.New().String()})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("expected Unauthenticated, got %v", err)
		}
	})

	t.Run("CreateInvite rejects untrusted caller", func(t *testing.T) {
		_, err := s.CreateInvite(untrustedCtx, &authv1.CreateInviteRequest{Caller: dummyCaller, OrgId: orgID, Email: "a@b.com", RoleId: "member"})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("expected Unauthenticated, got %v", err)
		}
	})

	t.Run("RevokeInvite rejects untrusted caller", func(t *testing.T) {
		_, err := s.RevokeInvite(untrustedCtx, &authv1.RevokeInviteRequest{Caller: dummyCaller, OrgId: orgID, InviteId: uuid.New().String()})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("expected Unauthenticated, got %v", err)
		}
	})

	t.Run("CreateAPIToken rejects untrusted caller", func(t *testing.T) {
		_, err := s.CreateAPIToken(untrustedCtx, &authv1.CreateAPITokenRequest{Caller: dummyCaller, OrgId: orgID, Name: "tok", Permissions: []string{"org:read"}})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("expected Unauthenticated, got %v", err)
		}
	})

	t.Run("ListAPITokens rejects untrusted caller", func(t *testing.T) {
		_, err := s.ListAPITokens(untrustedCtx, &authv1.ListAPITokensRequest{Caller: dummyCaller, OrgId: orgID})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("expected Unauthenticated, got %v", err)
		}
	})

	t.Run("RevokeAPIToken rejects untrusted caller", func(t *testing.T) {
		_, err := s.RevokeAPIToken(untrustedCtx, &authv1.RevokeAPITokenRequest{Caller: dummyCaller, OrgId: orgID, TokenId: uuid.New().String()})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("expected Unauthenticated, got %v", err)
		}
	})

	t.Run("ListAuditEvents rejects untrusted caller", func(t *testing.T) {
		_, err := s.ListAuditEvents(untrustedCtx, &authv1.ListAuditEventsRequest{Caller: dummyCaller, OrgId: orgID})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("expected Unauthenticated, got %v", err)
		}
	})
}
