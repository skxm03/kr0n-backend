package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/jwtkeys"
)

type mockAuthServer struct {
	authv1.UnimplementedAuthServiceServer
}

func (s *mockAuthServer) GetMe(ctx context.Context, req *authv1.GetMeRequest) (*authv1.GetMeResponse, error) {
	slog.Info("handled GetMe RPC")
	return &authv1.GetMeResponse{
		Id:          "e2e-user-001",
		Email:       "admin@kr0n.dev",
		DisplayName: "E2E Administrator",
		Status:      "active",
		CreatedAt:   timestamppb.Now(),
	}, nil
}

func (s *mockAuthServer) GetJWKS(ctx context.Context, req *authv1.GetJWKSRequest) (*authv1.GetJWKSResponse, error) {
	slog.Info("handled GetJWKS RPC")
	pub := jwtkeys.DevPrivateKey().Public().(ed25519.PublicKey)
	return &authv1.GetJWKSResponse{
		Keys: []*authv1.JWK{
			{
				Kty: "OKP",
				Crv: "Ed25519",
				Kid: "k1",
				Alg: "EdDSA",
				Use: "sig",
				X:   base64.RawURLEncoding.EncodeToString(pub),
			},
		},
	}, nil
}

func (s *mockAuthServer) ValidateAPIToken(ctx context.Context, req *authv1.ValidateAPITokenRequest) (*authv1.ValidateAPITokenResponse, error) {
	slog.Info("handled ValidateAPIToken RPC", "token", req.GetToken())
	if req.GetToken() == "kr0n_pat_valid_test_token" {
		return &authv1.ValidateAPITokenResponse{
			TokenId:     "pat-test-001",
			OrgId:       "org-e2e-1",
			UserId:      "pat-user-e2e",
			Permissions: []string{"read", "write"},
		}, nil
	}
	return nil, status.Error(codes.Unauthenticated, "invalid api token")
}

func (s *mockAuthServer) CheckPermission(ctx context.Context, req *authv1.CheckPermissionRequest) (*authv1.CheckPermissionResponse, error) {
	return &authv1.CheckPermissionResponse{Allowed: true}, nil
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "50051"
	}

	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		slog.Error("failed to listen", "error", err)
		os.Exit(1)
	}

	var srvOpts []grpc.ServerOption
	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")
	if certFile != "" && keyFile != "" {
		creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
		if err != nil {
			slog.Error("failed to load TLS credentials", "error", err)
			os.Exit(1)
		}
		srvOpts = append(srvOpts, grpc.Creds(creds))
	}

	srv := grpc.NewServer(srvOpts...)
	authv1.RegisterAuthServiceServer(srv, &mockAuthServer{})
	reflection.Register(srv)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		slog.Info("mock upstream gRPC server listening", "port", port)
		if err := srv.Serve(lis); err != nil {
			slog.Error("gRPC server failed", "error", err)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down mock upstream gRPC server")
	srv.GracefulStop()
}
