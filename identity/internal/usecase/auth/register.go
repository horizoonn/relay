package auth

import (
	"context"
	"fmt"
	"time"
	"uuid"

	"github.com/horizoonn/relay/identity/internal/domain"
	"github.com/horizoonn/relay/identity/internal/password"
)

func (s *Service) Register(ctx context.Context, email, value string) (uuid.UUID, error) {
	user, err := domain.NewUser(email, time.Now().UTC().Truncate(time.Microsecond))
	if err != nil {
		return uuid.Nil(), err
	}
	if err = password.ValidateNew(value); err != nil {
		return uuid.Nil(), err
	}
	hash, err := s.passwords.Hash(ctx, value)
	if err != nil {
		return uuid.Nil(), fmt.Errorf("hash registration password: %w", err)
	}
	err = s.tx.WithinTransaction(ctx, func(ctx context.Context) error {
		if createErr := s.users.Create(ctx, user, hash); createErr != nil {
			return fmt.Errorf("create account: %w", createErr)
		}
		if queueErr := s.verification.QueueVerification(ctx, user.Email); queueErr != nil {
			return fmt.Errorf("queue account verification: %w", queueErr)
		}
		return nil
	})
	if err != nil {
		return uuid.Nil(), fmt.Errorf("register account transaction: %w", err)
	}
	return user.ID, nil
}
