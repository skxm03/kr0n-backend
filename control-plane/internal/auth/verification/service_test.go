package verification

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

type mockRepository struct {
	mu     sync.Mutex
	tokens map[string]*Token // keyed by tokenHash
	users  map[uuid.UUID]*mockUser

	verifyAndConsumeFunc func(ctx context.Context, tokenHash string, now time.Time) (*Token, error)
}

type mockUser struct {
	id              uuid.UUID
	status          string
	emailVerifiedAt *time.Time
}

func newMockRepository() *mockRepository {
	return &mockRepository{
		tokens: make(map[string]*Token),
		users:  make(map[uuid.UUID]*mockUser),
	}
}

func (m *mockRepository) VerifyAndConsume(ctx context.Context, tokenHash string, now time.Time) (*Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.verifyAndConsumeFunc != nil {
		return m.verifyAndConsumeFunc(ctx, tokenHash, now)
	}

	tok, ok := m.tokens[tokenHash]
	if !ok {
		return nil, ErrInvalidToken
	}

	u, exists := m.users[tok.UserID]
	if !exists {
		return nil, ErrUserNotFound
	}

	if tok.ConsumedAt != nil {
		return nil, ErrTokenAlreadyConsumed
	}

	if !tok.ExpiresAt.After(now) {
		return nil, ErrTokenExpired
	}

	if u.status != "active" {
		return nil, ErrUserNotActive
	}

	// Mark user verified
	u.emailVerifiedAt = &now

	// Consume token
	tok.ConsumedAt = &now

	return tok, nil
}

func TestService_VerifyEmail_ValidToken(t *testing.T) {
	repo := newMockRepository()
	svc := NewService(repo)

	userID := uuid.New()
	repo.users[userID] = &mockUser{
		id:     userID,
		status: "active",
	}

	rawToken, _ := GenerateToken()
	tokenHash := HashToken(rawToken)
	now := time.Now().UTC()

	repo.tokens[tokenHash] = &Token{
		ID:        uuid.New(),
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}

	// 1. Valid token verifies user
	err := svc.VerifyEmail(context.Background(), rawToken)
	if err != nil {
		t.Fatalf("expected verification to succeed, got %v", err)
	}

	// 2. Token sets email_verified_at
	u := repo.users[userID]
	if u.emailVerifiedAt == nil {
		t.Fatal("expected user email_verified_at to be populated")
	}

	// 3. Token becomes unusable afterward (consumed)
	err = svc.VerifyEmail(context.Background(), rawToken)
	if !errors.Is(err, ErrTokenAlreadyConsumed) {
		t.Fatalf("expected ErrTokenAlreadyConsumed on reuse, got %v", err)
	}
}

func TestService_VerifyEmail_ExpiredToken(t *testing.T) {
	repo := newMockRepository()
	svc := NewService(repo)

	userID := uuid.New()
	repo.users[userID] = &mockUser{
		id:     userID,
		status: "active",
	}

	rawToken, _ := GenerateToken()
	tokenHash := HashToken(rawToken)
	now := time.Now().UTC()

	repo.tokens[tokenHash] = &Token{
		ID:        uuid.New(),
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(-1 * time.Hour), // Expired
		CreatedAt: now.Add(-24 * time.Hour),
	}

	// 4. Expired token fails
	err := svc.VerifyEmail(context.Background(), rawToken)
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatal("expected ErrTokenExpired to also wrap ErrInvalidToken")
	}
}

func TestService_VerifyEmail_InvalidToken(t *testing.T) {
	repo := newMockRepository()
	svc := NewService(repo)

	// 5. Invalid token fails
	t.Run("nonexistent token", func(t *testing.T) {
		err := svc.VerifyEmail(context.Background(), "unknown_token_123")
		if !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("expected ErrInvalidToken, got %v", err)
		}
	})

	t.Run("empty token", func(t *testing.T) {
		err := svc.VerifyEmail(context.Background(), "   ")
		if !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("expected ErrInvalidToken, got %v", err)
		}
	})
}

func TestService_VerifyEmail_AlreadyConsumed(t *testing.T) {
	repo := newMockRepository()
	svc := NewService(repo)

	userID := uuid.New()
	repo.users[userID] = &mockUser{
		id:     userID,
		status: "active",
	}

	rawToken, _ := GenerateToken()
	tokenHash := HashToken(rawToken)
	now := time.Now().UTC()
	consumedAt := now.Add(-5 * time.Minute)

	repo.tokens[tokenHash] = &Token{
		ID:         uuid.New(),
		UserID:     userID,
		TokenHash:  tokenHash,
		ExpiresAt:  now.Add(24 * time.Hour),
		ConsumedAt: &consumedAt,
		CreatedAt:  now.Add(-1 * time.Hour),
	}

	// 6. Already-consumed token fails
	err := svc.VerifyEmail(context.Background(), rawToken)
	if !errors.Is(err, ErrTokenAlreadyConsumed) {
		t.Fatalf("expected ErrTokenAlreadyConsumed, got %v", err)
	}
}

func TestService_VerifyEmail_InactiveAndNonexistentUser(t *testing.T) {
	// 7. Inactive/nonexistent user behavior
	t.Run("nonexistent user fails", func(t *testing.T) {
		repo := newMockRepository()
		svc := NewService(repo)

		nonexistentUserID := uuid.New()
		rawToken, _ := GenerateToken()
		tokenHash := HashToken(rawToken)
		now := time.Now().UTC()

		repo.tokens[tokenHash] = &Token{
			ID:        uuid.New(),
			UserID:    nonexistentUserID,
			TokenHash: tokenHash,
			ExpiresAt: now.Add(24 * time.Hour),
			CreatedAt: now,
		}

		err := svc.VerifyEmail(context.Background(), rawToken)
		if !errors.Is(err, ErrUserNotFound) {
			t.Fatalf("expected ErrUserNotFound, got %v", err)
		}
	})

	t.Run("inactive user fails", func(t *testing.T) {
		repo := newMockRepository()
		svc := NewService(repo)

		userID := uuid.New()
		repo.users[userID] = &mockUser{
			id:     userID,
			status: "suspended",
		}

		rawToken, _ := GenerateToken()
		tokenHash := HashToken(rawToken)
		now := time.Now().UTC()

		repo.tokens[tokenHash] = &Token{
			ID:        uuid.New(),
			UserID:    userID,
			TokenHash: tokenHash,
			ExpiresAt: now.Add(24 * time.Hour),
			CreatedAt: now,
		}

		err := svc.VerifyEmail(context.Background(), rawToken)
		if !errors.Is(err, ErrUserNotActive) {
			t.Fatalf("expected ErrUserNotActive, got %v", err)
		}
	})
}

func TestService_VerifyEmail_ConcurrentVerification(t *testing.T) {
	// 8. Concurrent verification requests result in exactly one successful verification
	repo := newMockRepository()
	svc := NewService(repo)

	userID := uuid.New()
	repo.users[userID] = &mockUser{
		id:     userID,
		status: "active",
	}

	rawToken, _ := GenerateToken()
	tokenHash := HashToken(rawToken)
	now := time.Now().UTC()

	repo.tokens[tokenHash] = &Token{
		ID:        uuid.New(),
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}

	const goroutines = 10
	var successCount int64
	var failureCount int64

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			err := svc.VerifyEmail(context.Background(), rawToken)
			if err == nil {
				atomic.AddInt64(&successCount, 1)
			} else {
				atomic.AddInt64(&failureCount, 1)
			}
		}()
	}

	wg.Wait()

	if successCount != 1 {
		t.Fatalf("expected exactly 1 successful verification, got %d", successCount)
	}
	if failureCount != goroutines-1 {
		t.Fatalf("expected %d failures, got %d", goroutines-1, failureCount)
	}
}
