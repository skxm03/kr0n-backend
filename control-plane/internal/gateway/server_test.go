package gateway

import (
	"context"
	"os"
	"testing"

	"google.golang.org/grpc"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/config"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
)

type mockAuthClient struct {
	authv1.AuthServiceClient
	jwksResp     *authv1.GetJWKSResponse
	jwksErr      error
	validateResp *authv1.ValidateAPITokenResponse
	validateErr  error
}

func (m *mockAuthClient) GetJWKS(ctx context.Context, in *authv1.GetJWKSRequest, opts ...grpc.CallOption) (*authv1.GetJWKSResponse, error) {
	return m.jwksResp, m.jwksErr
}

func (m *mockAuthClient) ValidateAPIToken(ctx context.Context, in *authv1.ValidateAPITokenRequest, opts ...grpc.CallOption) (*authv1.ValidateAPITokenResponse, error) {
	return m.validateResp, m.validateErr
}

func TestNewAppFailsWithoutYAMLConfig(t *testing.T) {
	if _, err := NewApp(&config.Config{}); err == nil {
		t.Fatal("expected startup error when GatewayConfigPath is empty, got nil")
	}

	if _, err := NewApp(&config.Config{GatewayConfigPath: "/nonexistent/path/gateway.yaml"}); err == nil {
		t.Fatal("expected startup error when YAML file does not exist, got nil")
	}
}

func TestNewAppFailsWhenServiceHasNoURL(t *testing.T) {
	tmpFile := t.TempDir() + "/gateway.yaml"
	yamlContent := `
gateway:
  http_addr: ":8080"
services:
  auth:
    enabled: true
  payments:
    enabled: false
`
	if err := os.WriteFile(tmpFile, []byte(yamlContent), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := NewApp(&config.Config{GatewayConfigPath: tmpFile}); err == nil {
		t.Fatal("expected startup error when defined services have no URL in YAML or .env, got nil")
	}
}

func TestGRPCJWKSProvider(t *testing.T) {
	mock := &mockAuthClient{
		jwksResp: &authv1.GetJWKSResponse{
			Keys: []*authv1.JWK{
				{
					Kid: "k1",
					Kty: "OKP",
					Alg: "EdDSA",
					Crv: "Ed25519",
					Use: "sig",
					X:   "test-key",
				},
			},
		},
	}
	provider := NewGRPCJWKSProvider(mock)
	keys, err := provider.FetchJWKS(context.Background())
	if err != nil {
		t.Fatalf("unexpected error fetching JWKS: %v", err)
	}
	if len(keys) != 1 || keys[0].Kid != "k1" || keys[0].X != "test-key" {
		t.Fatalf("unexpected keys: %+v", keys)
	}
}

func TestGRPCAPITokenVerifier(t *testing.T) {
	mock := &mockAuthClient{
		validateResp: &authv1.ValidateAPITokenResponse{
			UserId:      "usr-1",
			OrgId:       "org-1",
			TokenId:     "tok-1",
			Permissions: []string{"org:read"},
		},
	}
	verifier := NewGRPCAPITokenVerifier(mock)
	principal, err := verifier.VerifyAPIToken(context.Background(), "kr0n_pat_secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if principal.UserID != "usr-1" || principal.OrgID != "org-1" || principal.Kind != middleware.PrincipalKindAPIToken {
		t.Fatalf("unexpected principal: %+v", principal)
	}
}
