package account

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/horizoonn/relay/identity/internal/domain"
	"github.com/horizoonn/relay/identity/internal/password"
	"github.com/horizoonn/relay/identity/internal/secret"
)

type Service struct {
	notifier  ChangeNotifier
	users     UserRepository
	tokens    TokenRepository
	sessions  SessionRepository
	tx        Transactor
	passwords PasswordHasher
}

func NewService(
	users UserRepository,
	tokens TokenRepository,
	sessions SessionRepository,
	tx Transactor,
	passwords PasswordHasher,
	notifier ChangeNotifier,
) (*Service, error) {
	if users == nil || tokens == nil || sessions == nil || tx == nil || passwords == nil || notifier == nil {
		return nil, errors.New("account service requires repositories, transaction manager and password hasher")
	}
	return &Service{
		users:     users,
		tokens:    tokens,
		sessions:  sessions,
		tx:        tx,
		passwords: passwords,
		notifier:  notifier,
	}, nil
}

func (s *Service) VerifyEmail(ctx context.Context, raw string) error {
	initial, err := s.loadToken(ctx, raw, domain.VerifyEmail)
	if err != nil {
		return err
	}
	transactionErr := s.tx.WithinTransaction(ctx, func(ctx context.Context) error {
		_, current, lockErr := s.lockToken(ctx, initial, domain.VerifyEmail)
		if lockErr != nil {
			return lockErr
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		if err := s.consumeToken(ctx, current.Hash, now); err != nil {
			return err
		}
		if err := s.users.VerifyEmail(ctx, current.UserID, now); err != nil {
			return fmt.Errorf("confirm account email: %w", err)
		}
		return nil
	})
	if transactionErr != nil {
		return fmt.Errorf("verify account email transaction: %w", transactionErr)
	}
	return nil
}

func (s *Service) ResetPassword(ctx context.Context, raw, value string) error {
	initial, err := s.loadToken(ctx, raw, domain.ResetPassword)
	if err != nil {
		return err
	}
	if policyErr := password.ValidateNew(value); policyErr != nil {
		return policyErr
	}

	hash, err := s.passwords.Hash(ctx, value)
	if err != nil {
		return fmt.Errorf("hash replacement account password: %w", err)
	}
	transactionErr := s.tx.WithinTransaction(ctx, func(ctx context.Context) error {
		user, current, lockErr := s.lockToken(ctx, initial, domain.ResetPassword)
		if lockErr != nil {
			return lockErr
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		if err := s.consumeToken(ctx, current.Hash, now); err != nil {
			return err
		}
		if err := s.users.UpdatePasswordHash(ctx, current.UserID, hash, now); err != nil {
			return fmt.Errorf("replace account password: %w", err)
		}

		if err := s.users.VerifyEmail(ctx, current.UserID, now); err != nil {
			return fmt.Errorf("confirm account email: %w", err)
		}
		if err := s.sessions.RevokeAll(ctx, current.UserID, now); err != nil {
			return fmt.Errorf("revoke account sessions: %w", err)
		}
		if err := s.tokens.InvalidateResets(ctx, current.UserID, now); err != nil {
			return fmt.Errorf("invalidate password reset tokens: %w", err)
		}
		if err := s.notifier.QueuePasswordChanged(ctx, user.Email); err != nil {
			return fmt.Errorf("queue password change notice: %w", err)
		}
		return nil
	})
	if transactionErr != nil {
		return fmt.Errorf("reset account password transaction: %w", transactionErr)
	}
	return nil
}

func (s *Service) loadToken(
	ctx context.Context,
	raw string,
	purpose domain.AccountTokenPurpose,
) (domain.AccountToken, error) {
	hash, err := secret.Digest(raw)
	if err != nil {
		return domain.AccountToken{}, ErrInvalidToken
	}
	token, err := s.tokens.Get(ctx, hash)
	if errors.Is(err, domain.ErrNotFound) {
		return domain.AccountToken{}, ErrInvalidToken
	}
	if err != nil {
		return domain.AccountToken{}, fmt.Errorf("load account token: %w", err)
	}
	if err := token.Validate(); err != nil {
		return domain.AccountToken{}, fmt.Errorf("validate account token: %w", err)
	}
	if token.Hash != hash || token.Purpose != purpose || !token.Active(time.Now().UTC()) {
		return domain.AccountToken{}, ErrInvalidToken
	}
	return token, nil
}

func (s *Service) lockToken(
	ctx context.Context,
	initial domain.AccountToken,
	purpose domain.AccountTokenPurpose,
) (domain.User, domain.AccountToken, error) {
	user, err := s.users.GetForUpdate(ctx, initial.UserID)
	if errors.Is(err, domain.ErrNotFound) {
		return domain.User{}, domain.AccountToken{}, ErrInvalidToken
	}
	if err != nil {
		return domain.User{}, domain.AccountToken{}, fmt.Errorf("lock account token user: %w", err)
	}
	if validateErr := user.Validate(); validateErr != nil {
		return domain.User{}, domain.AccountToken{}, fmt.Errorf("validate account token user: %w", validateErr)
	}
	if user.State != domain.UserActive || user.ID != initial.UserID {
		return domain.User{}, domain.AccountToken{}, ErrInvalidToken
	}
	current, err := s.tokens.Get(ctx, initial.Hash)
	if errors.Is(err, domain.ErrNotFound) {
		return domain.User{}, domain.AccountToken{}, ErrInvalidToken
	}
	if err != nil {
		return domain.User{}, domain.AccountToken{}, fmt.Errorf("reload account token: %w", err)
	}
	if err := current.Validate(); err != nil {
		return domain.User{}, domain.AccountToken{}, fmt.Errorf("validate current account token: %w", err)
	}
	if current.UserID != user.ID ||
		current.Hash != initial.Hash ||
		current.Purpose != purpose ||
		!current.Active(time.Now().UTC()) {
		return domain.User{}, domain.AccountToken{}, ErrInvalidToken
	}
	return user, current, nil
}

func (s *Service) consumeToken(ctx context.Context, hash [32]byte, now time.Time) error {
	err := s.tokens.Consume(ctx, hash, now)
	if errors.Is(err, domain.ErrNotFound) {
		return ErrInvalidToken
	}
	if err != nil {
		return fmt.Errorf("consume account token: %w", err)
	}
	return nil
}
