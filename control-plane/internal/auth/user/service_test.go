package user

import (
	"context"
	"errors"
	"testing"
)

type mockRepository struct {
	createFunc func(ctx context.Context, u *User, passwordHash string) error
	created    []*User
}

func (m *mockRepository) CreateWithPassword(ctx context.Context, u *User, passwordHash string) error {
	if m.createFunc != nil {
		return m.createFunc(ctx, u, passwordHash)
	}
	m.created = append(m.created, u)
	return nil
}

type mockHasher struct {
	hashCalled     bool
	hashResult     string
	hashErr        error
	validatePolicy func(password string) error
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
