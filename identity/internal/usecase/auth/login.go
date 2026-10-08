package auth

import (
	"context"
	"errors"
	"fmt"
	"time"
	"uuid"

	"github.com/horizoonn/relay/identity/internal/domain"
	"github.com/horizoonn/relay/identity/internal/password"
	identitylimit "github.com/horizoonn/relay/identity/internal/ratelimit"
)

type LoginResult struct {
	UserID           uuid.UUID
	SessionID        uuid.UUID
	SessionExpiresAt time.Time
	AccessExpiresAt  time.Time
	AccessToken      string
	RefreshToken     string
	CSRFToken        string
}

func (s *Service) Login(ctx context.Context, email, value string) (LoginResult, error) {
	email, err := domain.NormalizeEmail(email)
	if err != nil || !password.ValidInput(value) {
		return LoginResult{}, ErrInvalidCredentials
	}
	if err = s.limiter.Allow(ctx, identitylimit.LoginAccount, email); err != nil {
		return LoginResult{}, fmt.Errorf("limit account login: %w", err)
	}
	user, hash, err := s.verifyPasswordCredentials(ctx, email, value)
	if err != nil {
		return LoginResult{}, err
	}
	if user.EmailVerifiedAt == nil {
		return LoginResult{}, ErrEmailNotVerified
	}
	needsRehash, err := password.NeedsRehash(hash)
	if err != nil {
		return LoginResult{}, fmt.Errorf("inspect password hash parameters: %w", err)
	}
	var replacementHash string
	if needsRehash {
		replacementHash, err = s.passwords.Hash(ctx, value)
		if err != nil {
			return LoginResult{}, fmt.Errorf("rehash login password: %w", err)
		}
	}
	return s.completeLogin(ctx, user.ID, hash, replacementHash)
}

func (s *Service) verifyPasswordCredentials(
	ctx context.Context,
	email string,
	value string,
) (domain.User, string, error) {
	user, hash, err := s.users.GetByEmailWithPasswordHash(ctx, email)
	missing := errors.Is(err, domain.ErrNotFound)
	if missing {
		hash = s.dummyHash
	} else if err != nil {
		return domain.User{}, "", fmt.Errorf("load password credentials: %w", err)
	}
	matched, err := s.passwords.Verify(ctx, value, hash)
	if err != nil {
		return domain.User{}, "", fmt.Errorf("verify login password: %w", err)
	}
	if !matched || missing {
		return domain.User{}, "", ErrInvalidCredentials
	}
	if err = user.Validate(); err != nil {
		return domain.User{}, "", fmt.Errorf("validate login user: %w", err)
	}
	if user.State != domain.UserActive {
		return domain.User{}, "", ErrInvalidCredentials
	}
	return user, hash, nil
}

func (s *Service) recheckPasswordCredentials(
	ctx context.Context,
	id uuid.UUID,
	verifiedHash string,
) (domain.User, error) {
	current, err := s.users.GetForUpdate(ctx, id)
	if errors.Is(err, domain.ErrNotFound) {
		return domain.User{}, ErrInvalidCredentials
	}
	if err != nil {
		return domain.User{}, fmt.Errorf("lock login user: %w", err)
	}
	if err = current.Validate(); err != nil {
		return domain.User{}, fmt.Errorf("validate locked login user: %w", err)
	}
	if current.State != domain.UserActive {
		return domain.User{}, ErrInvalidCredentials
	}
	if current.EmailVerifiedAt == nil {
		return domain.User{}, ErrEmailNotVerified
	}
	currentHash, err := s.users.GetPasswordHash(ctx, id)
	if errors.Is(err, domain.ErrNotFound) {
		return domain.User{}, ErrInvalidCredentials
	}
	if err != nil {
		return domain.User{}, fmt.Errorf("reload password credentials: %w", err)
	}
	if currentHash != verifiedHash {
		return domain.User{}, ErrInvalidCredentials
	}
	return current, nil
}
