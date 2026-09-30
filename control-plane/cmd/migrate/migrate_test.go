//go:build integration

package main

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/skxm03/kr0n-backend/control-plane/internal/config"
)

func TestMigrationsLifecycle(t *testing.T) {
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load() failed: %v", err)
	}

	db, err := sql.Open("pgx/v5", cfg.DatabaseURL)
	if err != nil {
		t.Fatalf("sql.Open() failed: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("database ping failed: %v", err)
	}

	m, closeMigrator, err := newMigrator(cfg.DatabaseURL)
	if err != nil {
		t.Fatalf("newMigrator failed: %v", err)
	}
	defer closeMigrator()

	// Step 1: Ensure clean state by rolling back if already applied
	_ = m.Down()

	// Step 2: Apply migration up
	t.Log("Step 2: Running migration up...")
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("migration up failed: %v", err)
	}

	version, dirty, err := m.Version()
	if err != nil {
		t.Fatalf("failed to get version: %v", err)
	}
	if version != 1 || dirty {
		t.Fatalf("expected version 1 (dirty: false), got version %d (dirty: %t)", version, dirty)
	}

	// Step 3: Migration up again (idempotency check)
	t.Log("Step 3: Checking migration idempotency...")
	if err := m.Up(); !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("expected migrate.ErrNoChange on second up, got: %v", err)
	}

	// Step 4: Schema verification
	t.Log("Step 4: Verifying schema tables...")
	expectedTables := []string{
		"users",
		"password_credentials",
		"oauth_identities",
		"sessions",
		"email_verification_tokens",
		"organizations",
		"roles",
		"permissions",
		"role_permissions",
		"organization_memberships",
		"outbox_events",
	}

	for _, table := range expectedTables {
		var exists bool
		query := `SELECT EXISTS (
			SELECT FROM information_schema.tables 
			WHERE table_schema = 'public' AND table_name = $1
		);`
		if err := db.QueryRowContext(ctx, query, table).Scan(&exists); err != nil {
			t.Fatalf("failed to query table existence for %q: %v", table, err)
		}
		if !exists {
			t.Fatalf("expected table %q to exist in database", table)
		}
	}

	// Verify RBAC Seed Data
	var roleCount int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM roles;").Scan(&roleCount); err != nil {
		t.Fatalf("failed to query roles count: %v", err)
	}
	if roleCount != 3 {
		t.Fatalf("expected 3 seeded roles, got %d", roleCount)
	}

	var permCount int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM permissions;").Scan(&permCount); err != nil {
		t.Fatalf("failed to query permissions count: %v", err)
	}
	if permCount != 7 {
		t.Fatalf("expected 7 seeded permissions, got %d", permCount)
	}

	// Step 5: Constraint verification
	t.Log("Step 5: Verifying constraints...")

	// 5.1 Create baseline user
	userID1, _ := uuid.NewV7()
	const user1Email = "alice@kr0n.dev"
	_, err = db.ExecContext(ctx, `
		INSERT INTO users (id, email, display_name) 
		VALUES ($1, $2, 'Alice');
	`, userID1, user1Email)
	if err != nil {
		t.Fatalf("failed to insert baseline user: %v", err)
	}

	// 5.2 Duplicate email rejected
	userID2, _ := uuid.NewV7()
	_, err = db.ExecContext(ctx, `
		INSERT INTO users (id, email, display_name) 
		VALUES ($1, $2, 'Alice Duplicate');
	`, userID2, user1Email)
	if err == nil {
		t.Fatal("expected duplicate email insert to fail, but it succeeded")
	}

	// 5.3 Un-canonical email rejected
	userID3, _ := uuid.NewV7()
	_, err = db.ExecContext(ctx, `
		INSERT INTO users (id, email, display_name) 
		VALUES ($1, 'BOB@KR0N.DEV', 'Bob');
	`, userID3)
	if err == nil {
		t.Fatal("expected uncanonical email insert to fail, but it succeeded")
	}

	// 5.4 Duplicate OAuth identity rejected
	oauthID1, _ := uuid.NewV7()
	_, err = db.ExecContext(ctx, `
		INSERT INTO oauth_identities (id, user_id, provider, provider_user_id)
		VALUES ($1, $2, 'github', 'gh_12345');
	`, oauthID1, userID1)
	if err != nil {
		t.Fatalf("failed to insert baseline oauth identity: %v", err)
	}

	oauthID2, _ := uuid.NewV7()
	_, err = db.ExecContext(ctx, `
		INSERT INTO oauth_identities (id, user_id, provider, provider_user_id)
		VALUES ($1, $2, 'github', 'gh_12345');
	`, oauthID2, userID2)
	if err == nil {
		t.Fatal("expected duplicate oauth provider+provider_user_id to fail, but it succeeded")
	}

	// 5.5 Duplicate organization slug rejected
	orgID1, _ := uuid.NewV7()
	_, err = db.ExecContext(ctx, `
		INSERT INTO organizations (id, name, slug)
		VALUES ($1, 'Acme Corp', 'acme');
	`, orgID1)
	if err != nil {
		t.Fatalf("failed to insert baseline organization: %v", err)
	}

	orgID2, _ := uuid.NewV7()
	_, err = db.ExecContext(ctx, `
		INSERT INTO organizations (id, name, slug)
		VALUES ($1, 'Acme Two', 'acme');
	`, orgID2)
	if err == nil {
		t.Fatal("expected duplicate organization slug to fail, but it succeeded")
	}

	// 5.6 Baseline membership and duplicate organization membership rejected
	memID1, _ := uuid.NewV7()
	_, err = db.ExecContext(ctx, `
		INSERT INTO organization_memberships (id, organization_id, user_id, role_id)
		VALUES ($1, $2, $3, 'owner');
	`, memID1, orgID1, userID1)
	if err != nil {
		t.Fatalf("failed to insert baseline membership: %v", err)
	}

	memID2, _ := uuid.NewV7()
	_, err = db.ExecContext(ctx, `
		INSERT INTO organization_memberships (id, organization_id, user_id, role_id)
		VALUES ($1, $2, $3, 'admin');
	`, memID2, orgID1, userID1)
	if err == nil {
		t.Fatal("expected duplicate organization membership to fail, but it succeeded")
	}

	// 5.7 Invalid foreign key rejected (membership with non-existent role)
	memID3, _ := uuid.NewV7()
	_, err = db.ExecContext(ctx, `
		INSERT INTO organization_memberships (id, organization_id, user_id, role_id)
		VALUES ($1, $2, $3, 'superhero');
	`, memID3, orgID1, userID2)
	if err == nil {
		t.Fatal("expected invalid role foreign key to fail, but it succeeded")
	}

	// 5.8 Duplicate role/permission relationship rejected
	_, err = db.ExecContext(ctx, `
		INSERT INTO role_permissions (role_id, permission_id)
		VALUES ('owner', 'org:read');
	`)
	if err == nil {
		t.Fatal("expected duplicate role_permission insert to fail, but it succeeded")
	}

	// 5.9 Unique session token hash enforced
	sessionID1, _ := uuid.NewV7()
	_, err = db.ExecContext(ctx, `
		INSERT INTO sessions (id, user_id, token_hash, expires_at)
		VALUES ($1, $2, 'hash_abc123', now() + interval '7 days');
	`, sessionID1, userID1)
	if err != nil {
		t.Fatalf("failed to insert baseline session: %v", err)
	}

	sessionID2, _ := uuid.NewV7()
	_, err = db.ExecContext(ctx, `
		INSERT INTO sessions (id, user_id, token_hash, expires_at)
		VALUES ($1, $2, 'hash_abc123', now() + interval '7 days');
	`, sessionID2, userID1)
	if err == nil {
		t.Fatal("expected duplicate session token_hash to fail, but it succeeded")
	}

	// 5.10 Unique email verification token hash enforced
	tokenID1, _ := uuid.NewV7()
	_, err = db.ExecContext(ctx, `
		INSERT INTO email_verification_tokens (id, user_id, token_hash, expires_at)
		VALUES ($1, $2, 'verify_hash_xyz', now() + interval '1 day');
	`, tokenID1, userID1)
	if err != nil {
		t.Fatalf("failed to insert baseline verification token: %v", err)
	}

	tokenID2, _ := uuid.NewV7()
	_, err = db.ExecContext(ctx, `
		INSERT INTO email_verification_tokens (id, user_id, token_hash, expires_at)
		VALUES ($1, $2, 'verify_hash_xyz', now() + interval '1 day');
	`, tokenID2, userID1)
	if err == nil {
		t.Fatal("expected duplicate verification token_hash to fail, but it succeeded")
	}

	// 5.11 Outbox event with UUID aggregate_id
	eventID, _ := uuid.NewV7()
	_, err = db.ExecContext(ctx, `
		INSERT INTO outbox_events (id, event_type, aggregate_type, aggregate_id, payload)
		VALUES ($1, 'auth.user.created', 'user', $2, '{"user_id": "test"}'::jsonb);
	`, eventID, userID1)
	if err != nil {
		t.Fatalf("failed to insert outbox event: %v", err)
	}

	// Step 6: Migration down
	t.Log("Step 6: Running migration down...")
	if err := m.Steps(-1); err != nil {
		t.Fatalf("migration down failed: %v", err)
	}

	for _, table := range expectedTables {
		var exists bool
		query := `SELECT EXISTS (
			SELECT FROM information_schema.tables 
			WHERE table_schema = 'public' AND table_name = $1
		);`
		if err := db.QueryRowContext(ctx, query, table).Scan(&exists); err != nil {
			t.Fatalf("failed to query table existence after down for %q: %v", table, err)
		}
		if exists {
			t.Fatalf("expected table %q to be dropped after migration down", table)
		}
	}

	// Step 7: Migration up again (re-apply)
	t.Log("Step 7: Re-applying migration up...")
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("migration up re-apply failed: %v", err)
	}

	versionAfterReapply, dirtyAfterReapply, err := m.Version()
	if err != nil {
		t.Fatalf("failed to get version after re-apply: %v", err)
	}
	if versionAfterReapply != 1 || dirtyAfterReapply {
		t.Fatalf("expected version 1 (dirty: false) after re-apply, got %d (dirty: %t)", versionAfterReapply, dirtyAfterReapply)
	}

	t.Log("Integration test completed successfully!")
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
