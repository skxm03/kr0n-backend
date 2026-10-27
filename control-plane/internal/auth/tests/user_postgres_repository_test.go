package tests

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/repository"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/service"
)

func TestUserPostgresRepository_CreateWithPassword_Success(t *testing.T) {
	pool := setupTestPool(t)
	repo := repository.NewPostgresUserRepository(pool)

	uniqueEmail := "user_" + uuid.New().String() + "@kr0n.dev"
	u, err := repository.NewUser(uniqueEmail, "Test User")
	if err != nil {
		t.Fatalf("NewUser failed: %v", err)
	}

	const passwordHash = "$2a$12$e8I7n.oE/1u9jFq7m5yRyeuG.F/5kX5g5g1"
	ctx := context.Background()

	err = repo.CreateWithPasswordAndVerificationToken(ctx, u, passwordHash, nil)
	if err != nil {
		t.Fatalf("CreateWithPasswordAndVerificationToken failed: %v", err)
	}

	// Verify users table row
	var (
		gotEmail       string
		gotDisplayName string
		gotStatus      string
	)
	err = pool.QueryRow(ctx, "SELECT email, display_name, status FROM users WHERE id = $1", u.ID).
		Scan(&gotEmail, &gotDisplayName, &gotStatus)
	if err != nil {
		t.Fatalf("failed to query users row: %v", err)
	}
	if gotEmail != uniqueEmail || gotDisplayName != "Test User" || gotStatus != "active" {
		t.Fatalf("unexpected user record: email=%q, name=%q, status=%q", gotEmail, gotDisplayName, gotStatus)
	}

	// Verify password_credentials table row
	var gotHash string
	err = pool.QueryRow(ctx, "SELECT password_hash FROM password_credentials WHERE user_id = $1", u.ID).
		Scan(&gotHash)
	if err != nil {
		t.Fatalf("failed to query password_credentials row: %v", err)
	}
	if gotHash != passwordHash {
		t.Fatalf("expected hash %q, got %q", passwordHash, gotHash)
	}
}

func TestUserPostgresRepository_CreateWithPassword_DuplicateEmail(t *testing.T) {
	pool := setupTestPool(t)
	repo := repository.NewPostgresUserRepository(pool)

	uniqueEmail := "dup_" + uuid.New().String() + "@kr0n.dev"
	u1, err := repository.NewUser(uniqueEmail, "User One")
	if err != nil {
		t.Fatalf("NewUser 1 failed: %v", err)
	}

	ctx := context.Background()
	const hash = "$2a$12$e8I7n.oE/1u9jFq7m5yRyeuG.F/5kX5g5g1"
	if err := repo.CreateWithPasswordAndVerificationToken(ctx, u1, hash, nil); err != nil {
		t.Fatalf("initial insert failed: %v", err)
	}

	// Try inserting second user with same email
	u2, err := repository.NewUser(uniqueEmail, "User Two")
	if err != nil {
		t.Fatalf("NewUser 2 failed: %v", err)
	}

	err = repo.CreateWithPasswordAndVerificationToken(ctx, u2, hash, nil)
	if err == nil {
		t.Fatal("expected duplicate email error, got nil")
	}
	if !errors.Is(err, repository.ErrEmailAlreadyExists) {
		t.Fatalf("expected ErrEmailAlreadyExists, got %v", err)
	}
}

func TestUserPostgresRepository_CreateWithPassword_RollbackOnCredentialFailure(t *testing.T) {
	pool := setupTestPool(t)
	repo := repository.NewPostgresUserRepository(pool)

	uniqueEmail := "rollback_" + uuid.New().String() + "@kr0n.dev"
	u, err := repository.NewUser(uniqueEmail, "Rollback User")
	if err != nil {
		t.Fatalf("NewUser failed: %v", err)
	}

	ctx := context.Background()
	// Empty password hash violates check constraint 'password_hash_non_empty'
	err = repo.CreateWithPasswordAndVerificationToken(ctx, u, "", nil)
	if err == nil {
		t.Fatal("expected failure on empty password hash, got nil")
	}

	// Ensure users row was rolled back and does not exist
	var exists bool
	err = pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)", u.ID).Scan(&exists)
	if err != nil {
		t.Fatalf("failed to query users existence: %v", err)
	}
	if exists {
		t.Fatal("expected users row to be rolled back, but it exists")
	}
}

func TestUserPostgresRepository_GetByEmailWithPassword_Success(t *testing.T) {
	pool := setupTestPool(t)
	repo := repository.NewPostgresUserRepository(pool)

	uniqueEmail := "lookup_" + uuid.New().String() + "@kr0n.dev"
	u, err := repository.NewUser(uniqueEmail, "Lookup User")
	if err != nil {
		t.Fatalf("NewUser failed: %v", err)
	}

	const passwordHash = "$2a$12$e8I7n.oE/1u9jFq7m5yRyeuG.F/5kX5g5g1"
	ctx := context.Background()

	err = repo.CreateWithPasswordAndVerificationToken(ctx, u, passwordHash, nil)
	if err != nil {
		t.Fatalf("CreateWithPasswordAndVerificationToken failed: %v", err)
	}

	gotUser, gotHash, err := repo.GetByEmailWithPassword(ctx, uniqueEmail)
	if err != nil {
		t.Fatalf("GetByEmailWithPassword failed: %v", err)
	}

	if gotUser.ID != u.ID {
		t.Fatalf("expected ID %v, got %v", u.ID, gotUser.ID)
	}
	if gotUser.Email != uniqueEmail {
		t.Fatalf("expected email %s, got %s", uniqueEmail, gotUser.Email)
	}
	if gotUser.DisplayName != "Lookup User" {
		t.Fatalf("expected display name Lookup User, got %s", gotUser.DisplayName)
	}
	if gotUser.Status != repository.StatusActive {
		t.Fatalf("expected status active, got %s", gotUser.Status)
	}
	if gotHash != passwordHash {
		t.Fatalf("expected password hash %s, got %s", passwordHash, gotHash)
	}
}

func TestUserPostgresRepository_GetByEmailWithPassword_NotFound(t *testing.T) {
	pool := setupTestPool(t)
	repo := repository.NewPostgresUserRepository(pool)

	ctx := context.Background()
	_, _, err := repo.GetByEmailWithPassword(ctx, "nonexistent@kr0n.dev")
	if !errors.Is(err, repository.ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
}

func TestUserPostgresRepository_CreateWithPasswordAndVerificationToken_Success(t *testing.T) {
	pool := setupTestPool(t)
	repo := repository.NewPostgresUserRepository(pool)
	ctx := context.Background()

	uniqueEmail := "atomic_user_" + uuid.New().String() + "@kr0n.dev"
	u, err := repository.NewUser(uniqueEmail, "Atomic User")
	if err != nil {
		t.Fatalf("NewUser failed: %v", err)
	}

	rawToken, err := repository.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}
	tokenHash := repository.HashToken(rawToken)

	now := time.Now().UTC()
	token := &repository.Token{
		ID:        uuid.New(),
		UserID:    u.ID,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}

	passwordHash := "$2a$12$mockpasswordhashforemailverificationatomic"
	err = repo.CreateWithPasswordAndVerificationToken(ctx, u, passwordHash, token)
	if err != nil {
		t.Fatalf("CreateWithPasswordAndVerificationToken failed: %v", err)
	}

	// 1. Verify user created with email_verified_at = NULL
	var (
		dbVerifiedAt *time.Time
		dbStatus     string
	)
	err = pool.QueryRow(ctx, "SELECT email_verified_at, status FROM users WHERE id = $1", u.ID).Scan(&dbVerifiedAt, &dbStatus)
	if err != nil {
		t.Fatalf("query users table failed: %v", err)
	}
	if dbVerifiedAt != nil {
		t.Fatal("expected users.email_verified_at to be NULL upon creation")
	}
	if dbStatus != "active" {
		t.Fatalf("expected status active, got %s", dbStatus)
	}

	// 2. Verify password_credentials created
	var credUserID uuid.UUID
	err = pool.QueryRow(ctx, "SELECT user_id FROM password_credentials WHERE user_id = $1", u.ID).Scan(&credUserID)
	if err != nil {
		t.Fatalf("query password_credentials failed: %v", err)
	}

	// 3. Verify token created with token_hash (NOT raw token)
	var (
		tokID         uuid.UUID
		tokConsumedAt *time.Time
	)
	err = pool.QueryRow(ctx, "SELECT id, consumed_at FROM email_verification_tokens WHERE token_hash = $1", tokenHash).Scan(&tokID, &tokConsumedAt)
	if err != nil {
		t.Fatalf("query email_verification_tokens failed: %v", err)
	}
	if tokID != token.ID {
		t.Fatalf("expected token ID %v, got %v", token.ID, tokID)
	}
	if tokConsumedAt != nil {
		t.Fatal("expected token to NOT be consumed upon creation")
	}

	// 4. Confirm raw verification token does NOT exist in PostgreSQL
	var rawCount int
	_ = pool.QueryRow(ctx, "SELECT count(*) FROM email_verification_tokens WHERE token_hash = $1", rawToken).Scan(&rawCount)
	if rawCount != 0 {
		t.Fatalf("CRITICAL SECURITY VIOLATION: raw verification token was found in PostgreSQL")
	}
}

func TestUserPostgresRepository_CreateWithPasswordAndVerificationToken_RollbackOnTokenError(t *testing.T) {
	pool := setupTestPool(t)
	repo := repository.NewPostgresUserRepository(pool)
	ctx := context.Background()

	// First create an existing token to cause a unique constraint violation on token_hash
	existingEmail := "existing_token_user_" + uuid.New().String() + "@kr0n.dev"
	u1, _ := repository.NewUser(existingEmail, "First User")
	tokenHash := repository.HashToken("collision_" + uuid.New().String())
	now := time.Now().UTC()

	token1 := &repository.Token{
		ID:        uuid.New(),
		UserID:    u1.ID,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}
	if err := repo.CreateWithPasswordAndVerificationToken(ctx, u1, "passhash1", token1); err != nil {
		t.Fatalf("setup first user failed: %v", err)
	}

	// Now try to create a second user with the same token_hash
	uniqueEmail2 := "failed_atomic_user_" + uuid.New().String() + "@kr0n.dev"
	u2, _ := repository.NewUser(uniqueEmail2, "Second User")
	token2 := &repository.Token{
		ID:        uuid.New(),
		UserID:    u2.ID,
		TokenHash: tokenHash, // duplicate!
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}

	err := repo.CreateWithPasswordAndVerificationToken(ctx, u2, "passhash2", token2)
	if err == nil {
		t.Fatal("expected token unique violation error, got nil")
	}

	// Verify atomicity: u2 must NOT exist in users table
	var count int
	_ = pool.QueryRow(ctx, "SELECT count(*) FROM users WHERE id = $1", u2.ID).Scan(&count)
	if count != 0 {
		t.Fatalf("expected user row to be rolled back, found count=%d", count)
	}

	// Verify password credential for u2 does NOT exist
	_ = pool.QueryRow(ctx, "SELECT count(*) FROM password_credentials WHERE user_id = $1", u2.ID).Scan(&count)
	if count != 0 {
		t.Fatalf("expected password_credentials row to be rolled back, found count=%d", count)
	}
}

func TestUserPostgresRepository_ResolveOAuthUser_ScenariosAndTakeoverDefense(t *testing.T) {
	pool := setupTestPool(t)
	repo := repository.NewPostgresUserRepository(pool)
	hasher := service.NewBcryptHasher(12)
	svc := service.NewUserService(repo, hasher, service.WithRequireVerifiedEmail(true))
	ctx := context.Background()
	now := time.Now().UTC()

	// 1. Provider email unverified or missing must be rejected
	if _, err := repo.ResolveOAuthUser(ctx, repository.OAuthProfile{
		Provider: "github", ProviderUserID: "gh_unv_" + uuid.NewString(), Email: "u@kr0n.dev", EmailVerified: false,
	}, now); !errors.Is(err, repository.ErrOAuthEmailNotVerified) {
		t.Fatalf("expected ErrOAuthEmailNotVerified for unverified email, got %v", err)
	}
	if _, err := repo.ResolveOAuthUser(ctx, repository.OAuthProfile{
		Provider: "github", ProviderUserID: "gh_empty_" + uuid.NewString(), Email: "", EmailVerified: true,
	}, now); !errors.Is(err, repository.ErrOAuthEmailNotVerified) {
		t.Fatalf("expected ErrOAuthEmailNotVerified for empty email, got %v", err)
	}

	// 2. Brand-new GitHub user -> creates verified user + oauth_identities
	newEmail := "gh_new_" + uuid.NewString() + "@kr0n.dev"
	newGHID := "gh_new_" + uuid.NewString()
	created, err := repo.ResolveOAuthUser(ctx, repository.OAuthProfile{
		Provider: "github", ProviderUserID: newGHID, Email: newEmail, EmailVerified: true, DisplayName: "New GH",
	}, now)
	if err != nil {
		t.Fatalf("ResolveOAuthUser new user: %v", err)
	}
	if created.Email != newEmail || created.EmailVerifiedAt == nil {
		t.Fatalf("expected verified new user, got %+v", created)
	}

	// 3. Existing OAuth identity -> resolves same user idempotently
	again, err := repo.ResolveOAuthUser(ctx, repository.OAuthProfile{
		Provider: "github", ProviderUserID: newGHID, Email: newEmail, EmailVerified: true, DisplayName: "New GH",
	}, now)
	if err != nil || again.ID != created.ID {
		t.Fatalf("expected existing OAuth identity to resolve to %s, got %+v (err=%v)", created.ID, again, err)
	}

	// 4. Existing account with VERIFIED email -> links OAuth while preserving verified password & sessions
	verifiedEmail := "gh_verified_" + uuid.NewString() + "@kr0n.dev"
	verifiedUser, err := svc.Register(ctx, service.RegisterParams{
		Email: verifiedEmail, Password: "LegitUserPassword123!", DisplayName: "Legit User",
	})
	if err != nil {
		t.Fatalf("Register verified user: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET email_verified_at = $1 WHERE id = $2`, now, verifiedUser.ID); err != nil {
		t.Fatalf("mark verified: %v", err)
	}
	legitSessionID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO sessions (id, user_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)
	`, legitSessionID, verifiedUser.ID, "legit_sess_"+uuid.NewString(), now.Add(time.Hour)); err != nil {
		t.Fatalf("insert legit session: %v", err)
	}

	linkedVerified, err := repo.ResolveOAuthUser(ctx, repository.OAuthProfile{
		Provider: "github", ProviderUserID: "gh_ver_" + uuid.NewString(), Email: verifiedEmail, EmailVerified: true, DisplayName: "Legit GH",
	}, now)
	if err != nil || linkedVerified.ID != verifiedUser.ID {
		t.Fatalf("link verified user: err=%v user=%+v", err, linkedVerified)
	}
	// Legitimate password login and session must still work!
	if _, err := svc.Authenticate(ctx, service.AuthenticateParams{Email: verifiedEmail, Password: "LegitUserPassword123!"}); err != nil {
		t.Fatalf("legitimate verified user's password must still work after OAuth link: %v", err)
	}
	var legitRevokedAt *time.Time
	_ = pool.QueryRow(ctx, `SELECT revoked_at FROM sessions WHERE id = $1`, legitSessionID).Scan(&legitRevokedAt)
	if legitRevokedAt != nil {
		t.Fatal("legitimate verified user's session must NOT be revoked on OAuth link")
	}

	// 5. Attack scenario (HIGH-02): Attacker pre-registers victim's email WITHOUT verifying it,
	// sets an attacker password, creates a session and a password-reset token. Victim then signs in
	// with GitHub using that verified email. Attacker must lose all access.
	victimEmail := "victim_" + uuid.NewString() + "@kr0n.dev"
	attackerPass := "AttackerChosenPass123!"
	squattedUser, err := svc.Register(ctx, service.RegisterParams{
		Email: victimEmail, Password: attackerPass, DisplayName: "Attacker Squat",
	})
	if err != nil {
		t.Fatalf("attacker pre-register: %v", err)
	}
	attackerSessionID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO sessions (id, user_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)
	`, attackerSessionID, squattedUser.ID, "attacker_sess_"+uuid.NewString(), now.Add(time.Hour)); err != nil {
		t.Fatalf("insert attacker session: %v", err)
	}
	attackerResetHash := repository.HashToken("attacker_reset_" + uuid.NewString())
	if err := repo.CreatePasswordResetToken(ctx, &repository.Token{
		ID: uuid.New(), UserID: squattedUser.ID, TokenHash: attackerResetHash, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}); err != nil {
		t.Fatalf("CreatePasswordResetToken: %v", err)
	}

	// Victim signs in via GitHub OAuth with verified victimEmail
	reclaimed, err := repo.ResolveOAuthUser(ctx, repository.OAuthProfile{
		Provider: "github", ProviderUserID: "gh_victim_" + uuid.NewString(), Email: victimEmail, EmailVerified: true, DisplayName: "Real Victim",
	}, now)
	if err != nil {
		t.Fatalf("victim ResolveOAuthUser: %v", err)
	}
	if reclaimed.ID != squattedUser.ID || reclaimed.EmailVerifiedAt == nil || reclaimed.DisplayName != "Real Victim" {
		t.Fatalf("unexpected reclaimed user: %+v", reclaimed)
	}

	// Attacker's password must NOT work!
	if _, err := svc.Authenticate(ctx, service.AuthenticateParams{Email: victimEmail, Password: attackerPass}); !errors.Is(err, repository.ErrInvalidCredentials) {
		t.Fatalf("CRITICAL: attacker password must be rejected after victim OAuth sign-in, got %v", err)
	}
	var credCount int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM password_credentials WHERE user_id = $1`, reclaimed.ID).Scan(&credCount)
	if credCount != 0 {
		t.Fatalf("expected unverified password_credentials to be deleted, found %d", credCount)
	}
	// Attacker's pre-existing session must be revoked!
	var attackerRevokedAt *time.Time
	_ = pool.QueryRow(ctx, `SELECT revoked_at FROM sessions WHERE id = $1`, attackerSessionID).Scan(&attackerRevokedAt)
	if attackerRevokedAt == nil {
		t.Fatal("CRITICAL: pre-existing session on unverified account must be revoked upon OAuth reclamation")
	}
	// Pending reset and verification tokens must be consumed!
	var unconsumedTokens int
	_ = pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM email_verification_tokens WHERE user_id = $1 AND consumed_at IS NULL) +
		       (SELECT count(*) FROM password_reset_tokens WHERE user_id = $1 AND consumed_at IS NULL)
	`, reclaimed.ID).Scan(&unconsumedTokens)
	if unconsumedTokens != 0 {
		t.Fatalf("expected all pending verification/reset tokens to be consumed on OAuth reclamation, got %d", unconsumedTokens)
	}

	// 6. Uniqueness conflict & rollback: trying to link a DIFFERENT GitHub account to the same user
	// must fail with ErrOAuthAccountConflict and leave the original identity intact.
	if _, err := repo.ResolveOAuthUser(ctx, repository.OAuthProfile{
		Provider: "github", ProviderUserID: "gh_impostor_" + uuid.NewString(), Email: victimEmail, EmailVerified: true, DisplayName: "Impostor",
	}, now); !errors.Is(err, repository.ErrOAuthAccountConflict) {
		t.Fatalf("expected ErrOAuthAccountConflict when linking second github identity to same user, got %v", err)
	}

	// 7. Concurrent OAuth callbacks for the same brand-new user resolve cleanly to the same user
	concEmail := "gh_conc_" + uuid.NewString() + "@kr0n.dev"
	concGHID := "gh_conc_" + uuid.NewString()
	var wg sync.WaitGroup
	results := make([]*repository.User, 6)
	errs := make([]error, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = repo.ResolveOAuthUser(ctx, repository.OAuthProfile{
				Provider: "github", ProviderUserID: concGHID, Email: concEmail, EmailVerified: true, DisplayName: "Conc",
			}, now)
		}(i)
	}
	wg.Wait()
	for i := 0; i < 6; i++ {
		if errs[i] != nil {
			t.Fatalf("concurrent callback %d failed: %v", i, errs[i])
		}
		if results[i].ID != results[0].ID {
			t.Fatalf("concurrent callbacks created distinct users: %s vs %s", results[0].ID, results[i].ID)
		}
	}
}

func TestUserPostgresRepository_TokenReplacementInvalidatesPriorTokens(t *testing.T) {
	pool := setupTestPool(t)
	repo := repository.NewPostgresUserRepository(pool)
	ctx := context.Background()
	now := time.Now().UTC()

	u, _ := repository.NewUser("tok_replace_"+uuid.NewString()+"@kr0n.dev", "Tok Replace")
	v1 := &repository.Token{ID: uuid.New(), UserID: u.ID, TokenHash: repository.HashToken("v1_" + uuid.NewString()), ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if err := repo.CreateWithPasswordAndVerificationToken(ctx, u, "hash", v1); err != nil {
		t.Fatalf("CreateWithPasswordAndVerificationToken: %v", err)
	}
	v2 := &repository.Token{ID: uuid.New(), UserID: u.ID, TokenHash: repository.HashToken("v2_" + uuid.NewString()), ExpiresAt: now.Add(time.Hour), CreatedAt: now.Add(time.Second)}
	if err := repo.CreateVerificationToken(ctx, v2); err != nil {
		t.Fatalf("CreateVerificationToken: %v", err)
	}
	var activeVerif int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM email_verification_tokens WHERE user_id = $1 AND consumed_at IS NULL`, u.ID).Scan(&activeVerif)
	if activeVerif != 1 {
		t.Fatalf("expected exactly 1 active verification token after replacement, got %d", activeVerif)
	}

	r1 := &repository.Token{ID: uuid.New(), UserID: u.ID, TokenHash: repository.HashToken("r1_" + uuid.NewString()), ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	r2 := &repository.Token{ID: uuid.New(), UserID: u.ID, TokenHash: repository.HashToken("r2_" + uuid.NewString()), ExpiresAt: now.Add(time.Hour), CreatedAt: now.Add(time.Second)}
	if err := repo.CreatePasswordResetToken(ctx, r1); err != nil {
		t.Fatalf("CreatePasswordResetToken r1: %v", err)
	}
	if err := repo.CreatePasswordResetToken(ctx, r2); err != nil {
		t.Fatalf("CreatePasswordResetToken r2: %v", err)
	}
	if _, err := repo.ConsumePasswordResetAndUpdatePassword(ctx, r1.TokenHash, "newhash", now.Add(2*time.Second)); !errors.Is(err, repository.ErrInvalidResetToken) {
		t.Fatalf("superseded reset token r1 must be rejected, got %v", err)
	}
	if _, err := repo.ConsumePasswordResetAndUpdatePassword(ctx, r2.TokenHash, "newhash", now.Add(2*time.Second)); err != nil {
		t.Fatalf("latest reset token r2 must succeed: %v", err)
	}
}
