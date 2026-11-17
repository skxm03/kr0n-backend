package gateway

import (
	"context"
	"time"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/jwtkeys"
	"github.com/skxm03/kr0n-backend/control-plane/internal/gateway/middleware"
)

// AuthServiceClient is an alias for the generated gRPC AuthServiceClient contract.
type AuthServiceClient = authv1.AuthServiceClient

// NewGRPCJWKSProvider adapts an AuthServiceClient into a jwtkeys.KeySetProvider.
func NewGRPCJWKSProvider(c AuthServiceClient) jwtkeys.KeySetProvider {
	return grpcJWKSProvider{client: c}
}

type grpcJWKSProvider struct {
	client AuthServiceClient
}

func (p grpcJWKSProvider) FetchJWKS(ctx context.Context) ([]jwtkeys.JWK, error) {
	resp, err := p.client.GetJWKS(ctx, &authv1.GetJWKSRequest{})
	if err != nil {
		return nil, err
	}
	out := make([]jwtkeys.JWK, 0, len(resp.GetKeys()))
	for _, k := range resp.GetKeys() {
		out = append(out, jwtkeys.JWK{
			Kty: k.GetKty(),
			Crv: k.GetCrv(),
			Kid: k.GetKid(),
			Alg: k.GetAlg(),
			Use: k.GetUse(),
			X:   k.GetX(),
		})
	}
	return out, nil
}

// NewGRPCAPITokenVerifier adapts an AuthServiceClient into a middleware.APITokenVerifier.
func NewGRPCAPITokenVerifier(c AuthServiceClient) middleware.APITokenVerifier {
	return grpcAPITokenVerifier{client: c}
}

type grpcAPITokenVerifier struct {
	client AuthServiceClient
}

func (v grpcAPITokenVerifier) VerifyAPIToken(ctx context.Context, rawToken string) (*middleware.Principal, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resp, err := v.client.ValidateAPIToken(ctx, &authv1.ValidateAPITokenRequest{Token: rawToken})
	if err != nil {
		return nil, err
	}
	return &middleware.Principal{
		UserID:      resp.GetUserId(),
		Kind:        middleware.PrincipalKindAPIToken,
		OrgID:       resp.GetOrgId(),
		TokenID:     resp.GetTokenId(),
		Permissions: resp.GetPermissions(),
	}, nil
}
