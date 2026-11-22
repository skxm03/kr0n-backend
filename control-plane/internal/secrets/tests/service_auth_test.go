package tests

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/skxm03/kr0n-backend/control-plane/gen/auth/v1"
	secretsv1 "github.com/skxm03/kr0n-backend/control-plane/gen/secrets/v1"
	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/crypto"
	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/handlers"
	"github.com/skxm03/kr0n-backend/control-plane/internal/secrets/service"
	"github.com/skxm03/kr0n-backend/control-plane/pkg/grpcauth"
)

func TestSecrets_ServiceAuthentication_Enforcement(t *testing.T) {
	ctx := context.Background()
	orgID := uuid.New()
	projID := uuid.New()
	ownerID := uuid.New()

	repo := newMemorySecretsRepo()
	repo.roles[ownerID] = "owner"
	repo.projects[projID] = orgID

	rawKEK, err := crypto.GenerateRandomKey()
	if err != nil {
		t.Fatalf("GenerateRandomKey: %v", err)
	}
	km, err := crypto.NewKeyManager(rawKEK, 1)
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}

	svc := service.NewSecretsService(
		repo,
		km,
		service.WithAuthorizer(repo),
		service.WithProjectVerifier(repo),
	)

	serviceAuthCfg := grpcauth.ServiceAuthConfig{
		Enabled:            true,
		RequireClientCert:  true,
		AllowedClientNames: []string{"kr0n-gateway", "kr0n-runner"},
	}

	srv := handlers.NewServer(
		svc,
		handlers.WithServiceAuthConfig(serviceAuthCfg),
	)

	// 1. Untrusted caller calling ResolveProjectSecrets -> MUST return Unauthenticated
	_, err = srv.ResolveProjectSecrets(ctx, &secretsv1.ResolveProjectSecretsRequest{
		ProjectId:   projID.String(),
		Environment: "production",
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated for untrusted ResolveProjectSecrets call, got %v", err)
	}

	// 2. Untrusted caller calling UpsertProjectEnvVars -> MUST return Unauthenticated
	caller := &authv1.CallerPrincipal{UserId: ownerID.String(), Kind: "session"}
	_, err = srv.UpsertProjectEnvVars(ctx, &secretsv1.UpsertProjectEnvVarsRequest{
		Caller:      caller,
		OrgId:       orgID.String(),
		ProjectId:   projID.String(),
		Environment: "production",
		Variables: []*secretsv1.EnvVarInput{
			{Key: "API_KEY", Value: "secret-123"},
		},
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated for untrusted UpsertProjectEnvVars call, got %v", err)
	}

	// 3. Authenticated caller from trusted service (e.g. gateway) -> SUCCEEDS
	trustedCtx := grpcauth.WithTrustedService(ctx, "kr0n-gateway")
	_, err = srv.UpsertProjectEnvVars(trustedCtx, &secretsv1.UpsertProjectEnvVarsRequest{
		Caller:      caller,
		OrgId:       orgID.String(),
		ProjectId:   projID.String(),
		Environment: "production",
		Variables: []*secretsv1.EnvVarInput{
			{Key: "API_KEY", Value: "secret-123"},
		},
	})
	if err != nil {
		t.Fatalf("expected trusted call to succeed, got %v", err)
	}

	// 4. Authenticated runner calling ResolveProjectSecrets -> SUCCEEDS
	runnerCtx := grpcauth.WithTrustedService(ctx, "kr0n-runner")
	res, err := srv.ResolveProjectSecrets(runnerCtx, &secretsv1.ResolveProjectSecretsRequest{
		ProjectId:   projID.String(),
		Environment: "production",
	})
	if err != nil {
		t.Fatalf("expected trusted runner call to succeed, got %v", err)
	}
	if res.GetSecrets()["API_KEY"] != "secret-123" {
		t.Fatalf("expected API_KEY=secret-123, got %q", res.GetSecrets()["API_KEY"])
	}
}
