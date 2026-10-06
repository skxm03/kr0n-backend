package user

import (
	"context"
	"errors"
	"testing"
)

type mockRepository struct {
	createFunc func(ctx context.Context, u *User, passwordHash string) error
	getFunc    func(ctx context.Context, email string) (*User, string, error)
	created    []*User
}

func (m *mockRepository) CreateWithPassword(ctx context.Context, u *User, passwordHash string) error {
	if m.createFunc != nil {
		return m.createFunc(ctx, u, passwordHash)
	}
	m.created = append(m.created, u)
	return nil
}

func (m *mockRepository) GetByEmailWithPassword(ctx context.Context, email string) (*User, string, error) {
	if m.getFunc != nil {
		return m.getFunc(ctx, email)
	}
	return nil, "", ErrUserNotFound
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
		createFunc: func(ctx context.Context, u *User, passwordHash string) error {
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
