package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/horizoonn/relay/identity/internal/secret"
)

type Service struct {
	users        UserRepository
	sessions     SessionRepository
	tx           Transactor
	issuer       AccessIssuer
	dummyHash    string
	passwords    PasswordHasher
	limiter      RateLimiter
	verification VerificationQueue
}

func NewService(
	ctx context.Context,
	users UserRepository,
	sessions SessionRepository,
	tx Transactor,
	issuer AccessIssuer,
	passwords PasswordHasher,
	limiter RateLimiter,
	verification VerificationQueue,
) (*Service, error) {
	if users == nil ||
		sessions == nil ||
		tx == nil ||
		issuer == nil ||
		limiter == nil ||
		verification == nil ||
		passwords == nil {
		return nil, errors.New("invalid auth service configuration")
	}
	value, err := secret.Generate()
	if err != nil {
		return nil, fmt.Errorf("generate login timing credential: %w", err)
	}
	dummyHash, err := passwords.Hash(ctx, value)
	if err != nil {
		return nil, fmt.Errorf("hash login timing credential: %w", err)
	}
	return &Service{
		users:        users,
		sessions:     sessions,
		tx:           tx,
		issuer:       issuer,
		dummyHash:    dummyHash,
		passwords:    passwords,
		limiter:      limiter,
		verification: verification,
	}, nil
}
