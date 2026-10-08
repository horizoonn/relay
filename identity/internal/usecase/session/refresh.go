package session

import (
	"context"
	"crypto/subtle"
	"fmt"
	"time"
	"uuid"

	"github.com/horizoonn/relay/identity/internal/domain"
	"github.com/horizoonn/relay/identity/internal/secret"
)

const RefreshReuseWindow = 10 * time.Second

type RefreshResult struct {
	UserID           uuid.UUID
	SessionID        uuid.UUID
	SessionExpiresAt time.Time
	AccessExpiresAt  time.Time
	AccessToken      string
	RefreshToken     string
}

func (s *Service) Refresh(
	ctx context.Context,
	rawRefresh string,
	rawCSRF string,
) (RefreshResult, error) {
	hash, err := secret.Digest(rawRefresh)
	if err != nil {
		return RefreshResult{}, ErrUnauthenticated
	}
	csrfHash, err := secret.Digest(rawCSRF)
	if err != nil {
		return RefreshResult{}, ErrCSRF
	}
	initial, err := s.sessions.GetByRefreshHash(ctx, hash)
	if err != nil {
		return RefreshResult{}, fmt.Errorf("load refresh session: %w", authenticationError(err))
	}
	var result RefreshResult
	var outcome error
	err = s.tx.WithinTransaction(ctx, func(ctx context.Context) error {
		user, current, lockErr := s.lockSession(ctx, initial)
		if lockErr != nil {
			return lockErr
		}
		if subtle.ConstantTimeCompare(current.CSRFHash[:], csrfHash[:]) != 1 {
			return ErrCSRF
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		if user.State != domain.UserActive || !current.Active(now) {
			return ErrUnauthenticated
		}
		credential, loadErr := s.loadRefreshCredential(ctx, hash, current, now)
		if loadErr != nil {
			return loadErr
		}
		if credential.UsedAt != nil {
			if now.Sub(*credential.UsedAt) <= RefreshReuseWindow {
				return ErrRefreshConflict
			}
			if revokeErr := s.sessions.Revoke(ctx, current.UserID, current.ID, now); revokeErr != nil {
				return fmt.Errorf("revoke replayed session: %w", revokeErr)
			}

			outcome = ErrUnauthenticated
			return nil
		}
		var rotateErr error
		result, rotateErr = s.rotateRefresh(ctx, current, credential, now)
		return rotateErr
	})
	if err != nil {
		return RefreshResult{}, fmt.Errorf("refresh session transaction: %w", err)
	}
	if outcome != nil {
		return RefreshResult{}, outcome
	}
	return result, nil
}

func (s *Service) lockSession(
	ctx context.Context,
	initial domain.Session,
) (domain.User, domain.Session, error) {
	if err := initial.Validate(); err != nil {
		return domain.User{}, domain.Session{}, fmt.Errorf("validate initial session: %w", err)
	}
	user, err := s.users.GetForUpdate(ctx, initial.UserID)
	if err != nil {
		return domain.User{}, domain.Session{}, fmt.Errorf("lock session user: %w", authenticationError(err))
	}
	if validateErr := user.Validate(); validateErr != nil {
		return domain.User{}, domain.Session{}, fmt.Errorf("validate locked session user: %w", validateErr)
	}
	if user.ID != initial.UserID {
		return domain.User{}, domain.Session{}, ErrUnauthenticated
	}
	current, err := s.sessions.GetForUpdate(ctx, initial.UserID, initial.ID)
	if err != nil {
		return domain.User{}, domain.Session{}, fmt.Errorf("lock session: %w", authenticationError(err))
	}
	if err := current.Validate(); err != nil {
		return domain.User{}, domain.Session{}, fmt.Errorf("validate locked session: %w", err)
	}
	if current.ID != initial.ID || current.UserID != initial.UserID {
		return domain.User{}, domain.Session{}, ErrUnauthenticated
	}
	return user, current, nil
}

func (s *Service) loadRefreshCredential(
	ctx context.Context,
	hash [32]byte,
	current domain.Session,
	now time.Time,
) (domain.RefreshCredential, error) {
	credential, err := s.sessions.GetRefreshCredential(ctx, hash)
	if err != nil {
		return domain.RefreshCredential{}, fmt.Errorf("load refresh credential: %w", authenticationError(err))
	}
	if validateErr := credential.Validate(); validateErr != nil {
		return domain.RefreshCredential{}, fmt.Errorf("validate refresh credential: %w", validateErr)
	}
	if credential.SessionID != current.ID || credential.TokenHash != hash ||
		credential.CreatedAt.Before(current.CreatedAt) || credential.ExpiresAt.After(current.ExpiresAt) {
		return domain.RefreshCredential{}, domain.ErrInvalidRefreshCredential
	}
	if now.Before(credential.CreatedAt) || !now.Before(credential.ExpiresAt) {
		return domain.RefreshCredential{}, ErrUnauthenticated
	}
	return credential, nil
}
