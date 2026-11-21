package resolver

import (
	"context"

	"github.com/google/uuid"

	secretsv1 "github.com/skxm03/kr0n-backend/control-plane/gen/secrets/v1"
)

// SecretResolver is a restricted internal capability strictly reserved for the trusted
// build and deployment execution engine to inject decrypted secrets into runtime workloads.
// It must NEVER be exposed through public HTTP or gRPC gateway routes, and callers must
// never log or persist the returned plaintext map.
type SecretResolver interface {
	ResolveProjectSecrets(ctx context.Context, projectID uuid.UUID, environment string) (map[string]string, error)
}

// GRPCClientResolver adapts a secretsv1.SecretsInternalServiceClient into a SecretResolver
// for remote build/deployment workers connecting to kr0n-secrets over internal mTLS.
type GRPCClientResolver struct {
	client secretsv1.SecretsInternalServiceClient
}

// NewGRPCClientResolver creates a SecretResolver backed by an internal gRPC connection to kr0n-secrets.
func NewGRPCClientResolver(client secretsv1.SecretsInternalServiceClient) *GRPCClientResolver {
	return &GRPCClientResolver{client: client}
}

// ResolveProjectSecrets calls SecretsInternalService.ResolveProjectSecrets over internal gRPC.
func (r *GRPCClientResolver) ResolveProjectSecrets(ctx context.Context, projectID uuid.UUID, environment string) (map[string]string, error) {
	resp, err := r.client.ResolveProjectSecrets(ctx, &secretsv1.ResolveProjectSecretsRequest{
		ProjectId:   projectID.String(),
		Environment: environment,
	})
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(resp.GetSecrets()))
	for k, v := range resp.GetSecrets() {
		out[k] = v
	}
	return out, nil
}
