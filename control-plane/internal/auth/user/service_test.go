package user

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/verification"
	"github.com/skxm03/kr0n-backend/control-plane/internal/email"
)

type mockRepository struct {
	createTokenFunc  func(ctx context.Context, u *User, passwordHash string, token *verification.Token) error
	getFunc          func(ctx context.Context, email string) (*User, string, error)
	getByIDFunc      func(ctx context.Context, id uuid.UUID) (*User, error)
	getByIDPwFunc    func(ctx context.Context, id uuid.UUID) (*User, string, error)
	recordFailFunc   func(ctx context.Context, userID uuid.UUID, maxAttempts int, lockoutDuration time.Duration, now time.Time) error
	resetFailFunc    func(ctx context.Context, userID uuid.UUID) error
	consumeResetFunc func(ctx context.Context, tokenHash, newPasswordHash string, now time.Time) (uuid.UUID, error)
	updatePwFunc     func(ctx context.Context, userID uuid.UUID, newPasswordHash string, revokeSessionExcept *uuid.UUID, now time.Time) error
	resolveOAuthFunc func(ctx context.Context, profile OAuthProfile, now time.Time) (*User, error)
	created          []*User
	createdTokens    []*verification.Token
	resetTokens      []*verification.Token
	failureRecorded  int
	failuresReset    bool
}

func (m *mockRepository) CreateWithPasswordAndVerificationToken(ctx context.Context, u *User, passwordHash string, token *verification.Token) error {
	if m.createTokenFunc != nil {
		return m.createTokenFunc(ctx, u, passwordHash, token)
	}
	m.created = append(m.created, u)
	if token != nil {
		m.createdTokens = append(m.createdTokens, token)
	}
	return nil
}

func (m *mockRepository) GetByEmailWithPassword(ctx context.Context, email string) (*User, string, error) {
	if m.getFunc != nil {
		return m.getFunc(ctx, email)
	}
	return nil, "", ErrUserNotFound
}

func (m *mockRepository) GetByID(ctx context.Context, id uuid.UUID) (*User, error) {
	if m.getByIDFunc != nil {
		return m.getByIDFunc(ctx, id)
	}
	return nil, ErrUserNotFound
}

func (m *mockRepository) GetByIDWithPassword(ctx context.Context, id uuid.UUID) (*User, string, error) {
	if m.getByIDPwFunc != nil {
		return m.getByIDPwFunc(ctx, id)
	}
	return nil, "", ErrUserNotFound
}

func (m *mockRepository) RecordLoginFailure(ctx context.Context, userID uuid.UUID, maxAttempts int, lockoutDuration time.Duration, now time.Time) error {
	m.failureRecorded++
	if m.recordFailFunc != nil {
		return m.recordFailFunc(ctx, userID, maxAttempts, lockoutDuration, now)
	}
	return nil
}

func (m *mockRepository) ResetLoginFailures(ctx context.Context, userID uuid.UUID) error {
	m.failuresReset = true
	if m.resetFailFunc != nil {
		return m.resetFailFunc(ctx, userID)
	}
	return nil
}

func (m *mockRepository) CreateVerificationToken(ctx context.Context, token *verification.Token) error {
	m.createdTokens = append(m.createdTokens, token)
	return nil
}

func (m *mockRepository) CreatePasswordResetToken(ctx context.Context, token *verification.Token) error {
	m.resetTokens = append(m.resetTokens, token)
	return nil
}

func (m *mockRepository) ConsumePasswordResetAndUpdatePassword(ctx context.Context, tokenHash, newPasswordHash string, now time.Time) (uuid.UUID, error) {
	if m.consumeResetFunc != nil {
		return m.consumeResetFunc(ctx, tokenHash, newPasswordHash, now)
	}
	return uuid.Nil, nil
}

func (m *mockRepository) UpdatePassword(ctx context.Context, userID uuid.UUID, newPasswordHash string, revokeSessionExcept *uuid.UUID, now time.Time) error {
	if m.updatePwFunc != nil {
		return m.updatePwFunc(ctx, userID, newPasswordHash, revokeSessionExcept, now)
	}
	return nil
}

func (m *mockRepository) ResolveOAuthUser(ctx context.Context, profile OAuthProfile, now time.Time) (*User, error) {
	if m.resolveOAuthFunc != nil {
		return m.resolveOAuthFunc(ctx, profile, now)
	}
	return &User{ID: uuid.New(), Email: profile.Email, DisplayName: profile.DisplayName, Status: StatusActive}, nil
}

type mockHasher struct {
	hashCalled     bool
	hashResult     string
	hashErr        error
	validatePolicy func(password string) error
	compareFunc    func(hash, password string) error
}

func (m *mockHasher) Hash(password string) (string, error) {
	m.hashCalled = true
	return m.hashResult, m.hashErr
}

func (m *mockHasher) ValidatePolicy(password string) error {
	if m.validatePolicy != nil {
		return m.validatePolicy(password)
	}
	return nil
}

func (m *mockHasher) Compare(hash, password string) error {
	if m.compareFunc != nil {
		return m.compareFunc(hash, password)
	}
	if hash != password {
		return errors.New("password mismatch")
	}
	return nil
}

func TestService_Register_Success(t *testing.T) {
	repo := &mockRepository{}
	hasher := &mockHasher{hashResult: "mock_bcrypt_hash"}
	svc := NewService(repo, hasher)

	u, err := svc.Register(context.Background(), RegisterParams{
		Email:       " Developer@kr0n.dev ",
		Password:    "ValidPassword123",
		DisplayName: "Kr0n Developer",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if u.Email != "developer@kr0n.dev" {
		t.Fatalf("expected canonical email developer@kr0n.dev, got %q", u.Email)
	}
	if u.DisplayName != "Kr0n Developer" {
		t.Fatalf("expected display name %q, got %q", "Kr0n Developer", u.DisplayName)
	}
	if !hasher.hashCalled {
		t.Fatal("expected hasher.Hash to be called")
	}
	if len(repo.created) != 1 {
		t.Fatalf("expected 1 user created in repo, got %d", len(repo.created))
	}
}

func TestService_Register_PolicyFailBeforeHash(t *testing.T) {
	repo := &mockRepository{}
	hasher := &mockHasher{
		validatePolicy: func(password string) error {
			return ErrInvalidPassword
		},
	}
	svc := NewService(repo, hasher)

	_, err := svc.Register(context.Background(), RegisterParams{
		Email:       "developer@kr0n.dev",
		Password:    "short",
		DisplayName: "Developer",
	})
	if !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("expected ErrInvalidPassword, got %v", err)
	}

	if hasher.hashCalled {
		t.Fatal("expected hasher.Hash NOT to be called when policy fails")
	}
	if len(repo.created) != 0 {
		t.Fatal("expected no repository calls when policy fails")
	}
}

func TestService_Register_DuplicateEmail(t *testing.T) {
	repo := &mockRepository{
		createTokenFunc: func(ctx context.Context, u *User, passwordHash string, token *verification.Token) error {
			return ErrEmailAlreadyExists
		},
	}
	hasher := &mockHasher{hashResult: "mock_hash"}
	svc := NewService(repo, hasher)

	_, err := svc.Register(context.Background(), RegisterParams{
		Email:       "existing@kr0n.dev",
		Password:    "ValidPassword123",
		DisplayName: "Existing User",
	})
	if !errors.Is(err, ErrEmailAlreadyExists) {
		t.Fatalf("expected ErrEmailAlreadyExists, got %v", err)
	}
}

func TestService_Authenticate_Success(t *testing.T) {
	existingUser := &User{
		Email:       "valid@kr0n.dev",
		DisplayName: "Valid User",
		Status:      StatusActive,
	}
	repo := &mockRepository{
		getFunc: func(ctx context.Context, email string) (*User, string, error) {
			if email == "valid@kr0n.dev" {
				return existingUser, "hashed_pw", nil
			}
			return nil, "", ErrUserNotFound
		},
	}
	hasher := &mockHasher{
		compareFunc: func(hash, password string) error {
			if hash == "hashed_pw" && password == "secret" {
				return nil
			}
			return errors.New("mismatch")
		},
	}
	svc := NewService(repo, hasher)

	u, err := svc.Authenticate(context.Background(), AuthenticateParams{
		Email:    "  VALID@kr0n.dev ",
		Password: "secret",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.Email != "valid@kr0n.dev" {
		t.Fatalf("expected user email valid@kr0n.dev, got %s", u.Email)
	}
}

func TestService_Authenticate_UserNotFound(t *testing.T) {
	dummyCompareCalled := false
	repo := &mockRepository{
		getFunc: func(ctx context.Context, email string) (*User, string, error) {
			return nil, "", ErrUserNotFound
		},
	}
	hasher := &mockHasher{
		compareFunc: func(hash, password string) error {
			dummyCompareCalled = true
			return errors.New("mismatch")
		},
	}
	svc := NewService(repo, hasher)

	_, err := svc.Authenticate(context.Background(), AuthenticateParams{
		Email:    "nonexistent@kr0n.dev",
		Password: "secret",
	})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
	if !dummyCompareCalled {
		t.Fatal("expected dummy compare to be called to prevent timing enumeration")
	}
}

func TestService_Authenticate_WrongPassword(t *testing.T) {
	existingUser := &User{
		Email:       "valid@kr0n.dev",
		DisplayName: "Valid User",
		Status:      StatusActive,
	}
	repo := &mockRepository{
		getFunc: func(ctx context.Context, email string) (*User, string, error) {
			return existingUser, "hashed_pw", nil
		},
	}
	hasher := &mockHasher{
		compareFunc: func(hash, password string) error {
			return errors.New("bcrypt mismatch")
		},
	}
	svc := NewService(repo, hasher)

	_, err := svc.Authenticate(context.Background(), AuthenticateParams{
		Email:    "valid@kr0n.dev",
		Password: "wrongpassword",
	})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestService_Authenticate_InactiveUser(t *testing.T) {
	statuses := []Status{StatusSuspended, StatusDeactivated}
	for _, st := range statuses {
		t.Run(string(st), func(t *testing.T) {
			existingUser := &User{
				Email:       "valid@kr0n.dev",
				DisplayName: "Valid User",
				Status:      st,
			}
			repo := &mockRepository{
				getFunc: func(ctx context.Context, email string) (*User, string, error) {
					return existingUser, "hashed_pw", nil
				},
			}
			hasher := &mockHasher{
				compareFunc: func(hash, password string) error {
					return nil
				},
			}
			svc := NewService(repo, hasher)

			_, err := svc.Authenticate(context.Background(), AuthenticateParams{
				Email:    "valid@kr0n.dev",
				Password: "secret",
			})
			if !errors.Is(err, ErrUserNotActive) {
				t.Fatalf("expected ErrUserNotActive, got %v", err)
			}
		})
	}
}

func TestService_Authenticate_RepositoryError(t *testing.T) {
	repo := &mockRepository{
		getFunc: func(ctx context.Context, email string) (*User, string, error) {
			return nil, "", errors.New("db connection failure")
		},
	}
	hasher := &mockHasher{}
	svc := NewService(repo, hasher)

	_, err := svc.Authenticate(context.Background(), AuthenticateParams{
		Email:    "valid@kr0n.dev",
		Password: "secret",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if errors.Is(err, ErrInvalidCredentials) {
		t.Fatal("expected internal db error to not be masked as ErrInvalidCredentials")
	}
}

func TestService_Register_CreatesVerificationTokenAndDispatchesEmail(t *testing.T) {
	repo := &mockRepository{}
	hasher := &mockHasher{hashResult: "mock_bcrypt_hash"}
	emailSender := email.NewInMemorySender()

	svc := NewService(repo, hasher,
		WithEmailSender(emailSender),
		WithTokenLifetime(24*time.Hour),
	)

	u, err := svc.Register(context.Background(), RegisterParams{
		Email:       "newuser@kr0n.dev",
		Password:    "SecurePassword123!",
		DisplayName: "New User",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 1. User starts with email_verified_at = NULL
	if u.EmailVerifiedAt != nil {
		t.Fatal("expected newly registered user to have email_verified_at = nil")
	}

	// 2. Verification token is created atomically in repository
	if len(repo.createdTokens) != 1 {
		t.Fatalf("expected 1 verification token created, got %d", len(repo.createdTokens))
	}
	tok := repo.createdTokens[0]
	if tok.UserID != u.ID {
		t.Fatalf("expected token user ID %v, got %v", u.ID, tok.UserID)
	}
	if tok.ConsumedAt != nil {
		t.Fatal("expected token to NOT be consumed")
	}
	if tok.TokenHash == "" {
		t.Fatal("expected non-empty token hash")
	}

	// 3. Email sender captured verification email
	msgs := emailSender.Messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 email dispatched, got %d", len(msgs))
	}
	msg := msgs[0]
	if msg.Recipient != "newuser@kr0n.dev" {
		t.Fatalf("expected recipient %q, got %q", "newuser@kr0n.dev", msg.Recipient)
	}
	if msg.RawToken == "" {
		t.Fatal("expected non-empty raw token in email")
	}

	// 4. Stored hash corresponds to the raw token sent via email
	if !verification.VerifyTokenHash(msg.RawToken, tok.TokenHash) {
		t.Fatal("persisted token hash does not match raw token sent in email")
	}
	// Verify raw token is NOT stored directly
	if tok.TokenHash == msg.RawToken {
		t.Fatal("CRITICAL: raw token was stored as token hash")
	}
}

func TestService_Register_EmailSenderFailureDoesNotRollbackRegistration(t *testing.T) {
	repo := &mockRepository{}
	hasher := &mockHasher{hashResult: "mock_bcrypt_hash"}
	emailSender := email.NewInMemorySender()
	emailSender.SetFailNext(errors.New("mail server unreachable"))

	svc := NewService(repo, hasher,
		WithEmailSender(emailSender),
	)

	u, err := svc.Register(context.Background(), RegisterParams{
		Email:       "survivor@kr0n.dev",
		Password:    "SecurePassword123!",
		DisplayName: "Survivor User",
	})
	if err != nil {
		t.Fatalf("expected registration to succeed even if email delivery fails, got %v", err)
	}

	if len(repo.created) != 1 {
		t.Fatal("expected user to be persisted despite email failure")
	}
	if len(repo.createdTokens) != 1 {
		t.Fatal("expected token to be persisted despite email failure")
	}
	if u.Email != "survivor@kr0n.dev" {
		t.Fatalf("expected email survivor@kr0n.dev, got %s", u.Email)
	}
}

func TestService_Register_DoesNotLogRawToken(t *testing.T) {
	var buf bytes.Buffer
	origOutput := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(origOutput)

	repo := &mockRepository{}
	hasher := &mockHasher{hashResult: "mock_bcrypt_hash"}
	emailSender := email.NewInMemorySender()
	// Simulate email failure so error logging is triggered
	emailSender.SetFailNext(errors.New("smtp timeout"))

	svc := NewService(repo, hasher,
		WithEmailSender(emailSender),
	)

	_, err := svc.Register(context.Background(), RegisterParams{
		Email:       "logging_test@kr0n.dev",
		Password:    "SecurePassword123!",
		DisplayName: "Logging Test",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	logContent := buf.String()
	if strings.Contains(logContent, "failed to dispatch verification email") {
		// Verify no 64-char hex token in logs
		words := strings.Fields(logContent)
		for _, w := range words {
			if len(w) == 64 {
				t.Fatalf("CRITICAL SECURITY VIOLATION: possible raw token in log: %s", w)
			}
		}
	}
}

func TestService_Authenticate_LockoutAndRequireVerifiedEmail(t *testing.T) {
	future := time.Now().UTC().Add(10 * time.Minute)
	lockedUser := &User{
		ID:          uuid.New(),
		Email:       "locked@kr0n.dev",
		DisplayName: "Locked",
		Status:      StatusActive,
		LockedUntil: &future,
	}
	unverifiedUser := &User{
		ID:                  uuid.New(),
		Email:               "unverified@kr0n.dev",
		DisplayName:         "Unverified",
		Status:              StatusActive,
		FailedLoginAttempts: 2,
	}

	repo := &mockRepository{
		getFunc: func(ctx context.Context, email string) (*User, string, error) {
			switch email {
			case "locked@kr0n.dev":
				return lockedUser, "pw", nil
			case "unverified@kr0n.dev":
				return unverifiedUser, "pw", nil
			default:
				return nil, "", ErrUserNotFound
			}
		},
	}
	hasher := &mockHasher{}
	svc := NewService(repo, hasher, WithRequireVerifiedEmail(true), WithLockoutPolicy(5, 15*time.Minute))

	// 1. Locked user should get ErrInvalidCredentials even with valid password
	if _, err := svc.Authenticate(context.Background(), AuthenticateParams{Email: "locked@kr0n.dev", Password: "pw"}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for locked user, got %v", err)
	}

	// 2. Wrong password on active user records failure
	if _, err := svc.Authenticate(context.Background(), AuthenticateParams{Email: "unverified@kr0n.dev", Password: "wrong"}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for wrong password, got %v", err)
	}
	if repo.failureRecorded != 1 {
		t.Fatalf("expected 1 failure recorded, got %d", repo.failureRecorded)
	}

	// 3. Correct password resets failure count, then fails with ErrEmailNotVerified when required
	if _, err := svc.Authenticate(context.Background(), AuthenticateParams{Email: "unverified@kr0n.dev", Password: "pw"}); !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("expected ErrEmailNotVerified, got %v", err)
	}
	if !repo.failuresReset {
		t.Fatal("expected failures to be reset on valid password")
	}

	// 4. Verified user succeeds
	now := time.Now().UTC()
	unverifiedUser.EmailVerifiedAt = &now
	if _, err := svc.Authenticate(context.Background(), AuthenticateParams{Email: "unverified@kr0n.dev", Password: "pw"}); err != nil {
		t.Fatalf("expected verified user to succeed, got %v", err)
	}
}

func TestService_ResendVerification(t *testing.T) {
	unverifiedUser := &User{
		ID:          uuid.New(),
		Email:       "unverified@kr0n.dev",
		DisplayName: "Unverified",
		Status:      StatusActive,
	}
	now := time.Now().UTC()
	verifiedUser := &User{
		ID:              uuid.New(),
		Email:           "verified@kr0n.dev",
		DisplayName:     "Verified",
		Status:          StatusActive,
		EmailVerifiedAt: &now,
	}

	repo := &mockRepository{
		getFunc: func(ctx context.Context, email string) (*User, string, error) {
			switch email {
			case "unverified@kr0n.dev":
				return unverifiedUser, "pw", nil
			case "verified@kr0n.dev":
				return verifiedUser, "pw", nil
			default:
				return nil, "", ErrUserNotFound
			}
		},
	}
	sender := email.NewInMemorySender()
	svc := NewService(repo, &mockHasher{}, WithEmailSender(sender))

	// Non-existent user -> nil, no email sent
	if err := svc.ResendVerification(context.Background(), "nobody@kr0n.dev"); err != nil {
		t.Fatalf("expected nil for unknown email, got %v", err)
	}
	// Already verified user -> nil, no email sent
	if err := svc.ResendVerification(context.Background(), "verified@kr0n.dev"); err != nil {
		t.Fatalf("expected nil for verified email, got %v", err)
	}
	if len(sender.Messages()) != 0 {
		t.Fatalf("expected 0 emails sent so far, got %d", len(sender.Messages()))
	}

	// Unverified user -> token persisted and email sent
	if err := svc.ResendVerification(context.Background(), "unverified@kr0n.dev"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sender.Messages()) != 1 {
		t.Fatalf("expected 1 verification email, got %d", len(sender.Messages()))
	}
}

func TestService_PasswordResetAndChangePassword(t *testing.T) {
	u := &User{
		ID:          uuid.New(),
		Email:       "reset@kr0n.dev",
		DisplayName: "Reset User",
		Status:      StatusActive,
	}
	var consumedHash, updatedHash string
	repo := &mockRepository{
		getFunc: func(ctx context.Context, email string) (*User, string, error) {
			if email == "reset@kr0n.dev" {
				return u, "old_pw", nil
			}
			return nil, "", ErrUserNotFound
		},
		getByIDPwFunc: func(ctx context.Context, id uuid.UUID) (*User, string, error) {
			if id == u.ID {
				return u, "old_pw", nil
			}
			return nil, "", ErrUserNotFound
		},
		getByIDFunc: func(ctx context.Context, id uuid.UUID) (*User, error) {
			if id == u.ID {
				return u, nil
			}
			return nil, ErrUserNotFound
		},
		consumeResetFunc: func(ctx context.Context, tokenHash, newPasswordHash string, now time.Time) (uuid.UUID, error) {
			consumedHash = tokenHash
			updatedHash = newPasswordHash
			return u.ID, nil
		},
		updatePwFunc: func(ctx context.Context, userID uuid.UUID, newPasswordHash string, revokeSessionExcept *uuid.UUID, now time.Time) error {
			updatedHash = newPasswordHash
			return nil
		},
	}
	sender := email.NewInMemorySender()
	hasher := &mockHasher{hashResult: "new_hashed_pw"}
	svc := NewService(repo, hasher, WithEmailSender(sender), WithPasswordResetTokenLifetime(30*time.Minute))

	// 1. RequestPasswordReset for unknown user -> nil, no email
	if err := svc.RequestPasswordReset(context.Background(), "unknown@kr0n.dev"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sender.Messages()) != 0 {
		t.Fatal("expected no reset email for unknown user")
	}

	// 2. RequestPasswordReset for active user -> sends reset email
	if err := svc.RequestPasswordReset(context.Background(), "reset@kr0n.dev"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resetMsgs := sender.Messages()
	if len(resetMsgs) != 1 {
		t.Fatalf("expected 1 reset email, got %d", len(resetMsgs))
	}

	// 3. ConfirmPasswordReset verifies hash matches token
	if _, err := svc.ConfirmPasswordReset(context.Background(), resetMsgs[0].RawToken, "NewValidPassword123!"); err != nil {
		t.Fatalf("ConfirmPasswordReset: %v", err)
	}
	if consumedHash != verification.HashToken(resetMsgs[0].RawToken) {
		t.Fatal("expected consumedHash to match raw reset token hash")
	}
	if updatedHash != "new_hashed_pw" {
		t.Fatalf("expected updatedHash 'new_hashed_pw', got %q", updatedHash)
	}

	// 4. ChangePassword with wrong current password fails
	if err := svc.ChangePassword(context.Background(), u.ID, "wrong_pw", "AnotherPassword123!", nil); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}

	// 5. ChangePassword with valid current password succeeds
	updatedHash = ""
	if err := svc.ChangePassword(context.Background(), u.ID, "old_pw", "AnotherPassword123!", nil); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if updatedHash != "new_hashed_pw" {
		t.Fatalf("expected updatedHash 'new_hashed_pw', got %q", updatedHash)
	}

	// 6. GetProfile returns user
	prof, err := svc.GetProfile(context.Background(), u.ID)
	if err != nil || prof.Email != u.Email {
		t.Fatalf("GetProfile failed: %v, %+v", err, prof)
	}
}

func TestService_ResolveOAuthUser(t *testing.T) {
	var gotProfile OAuthProfile
	repo := &mockRepository{
		resolveOAuthFunc: func(ctx context.Context, profile OAuthProfile, now time.Time) (*User, error) {
			gotProfile = profile
			return &User{ID: uuid.New(), Email: profile.Email, DisplayName: profile.DisplayName, Status: StatusActive}, nil
		},
	}
	svc := NewService(repo, &mockHasher{})

	// Unverified email must be rejected
	if _, err := svc.ResolveOAuthUser(context.Background(), OAuthProfile{
		Provider: "github", ProviderUserID: "123", Email: "unv@kr0n.dev", EmailVerified: false,
	}); !errors.Is(err, ErrOAuthEmailNotVerified) {
		t.Fatalf("expected ErrOAuthEmailNotVerified, got %v", err)
	}

	// Verified email is canonicalized and passed to repository
	u, err := svc.ResolveOAuthUser(context.Background(), OAuthProfile{
		Provider: "github", ProviderUserID: "123", Email: "  OCTO@Kr0n.dev ", EmailVerified: true, DisplayName: "Octo",
	})
	if err != nil || u.Email != "octo@kr0n.dev" || gotProfile.Email != "octo@kr0n.dev" {
		t.Fatalf("unexpected result: err=%v u=%+v gotProfile=%+v", err, u, gotProfile)
	}
}
