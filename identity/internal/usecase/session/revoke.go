package session

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"
	"uuid"

	"github.com/horizoonn/relay/identity/internal/domain"
	"github.com/horizoonn/relay/identity/internal/secret"
)

func (s *Service) Revoke(
	ctx context.Context,
	userID uuid.UUID,
	callerID uuid.UUID,
	targetID uuid.UUID,
	rawCSRF string,
) error {
	if targetID == uuid.Nil() {
		return ErrInvalidQuery
	}
	err := s.tx.WithinTransaction(ctx, func(ctx context.Context) error {
		current, err := s.lockActiveCaller(ctx, userID, callerID, rawCSRF)
		if err != nil {
			return err
		}
		target := current
		if targetID != current.ID {
			target, err = s.sessions.GetForUpdate(ctx, userID, targetID)
			if errors.Is(err, domain.ErrNotFound) {
				return ErrSessionNotFound
			}
			if err != nil {
				return fmt.Errorf("lock revocation target: %w", err)
			}
			if err := target.Validate(); err != nil {
				return fmt.Errorf("validate revocation target: %w", err)
			}
			if target.ID != targetID || target.UserID != userID {
				return ErrSessionNotFound
			}
		}
		now := time.Now().UTC()
		if target.RevokedAt != nil || !now.Before(target.ExpiresAt) {
			return nil
		}
		if revokeErr := s.sessions.Revoke(ctx, userID, targetID, now); revokeErr != nil {
			return fmt.Errorf("persist session revocation: %w", revokeErr)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("revoke session transaction: %w", err)
	}
	return nil
}

func (s *Service) RevokeAll(
	ctx context.Context,
	userID uuid.UUID,
	callerID uuid.UUID,
	rawCSRF string,
) error {
	err := s.tx.WithinTransaction(ctx, func(ctx context.Context) error {
		if _, err := s.lockActiveCaller(ctx, userID, callerID, rawCSRF); err != nil {
			return err
		}
		if revokeErr := s.sessions.RevokeAll(ctx, userID, time.Now().UTC()); revokeErr != nil {
			return fmt.Errorf("persist all session revocations: %w", revokeErr)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("revoke all sessions transaction: %w", err)
	}
	return nil
}

func (s *Service) lockActiveCaller(
	ctx context.Context,
	userID, callerID uuid.UUID,
	rawCSRF string,
) (domain.Session, error) {
	if userID == uuid.Nil() || callerID == uuid.Nil() {
		return domain.Session{}, ErrUnauthenticated
	}
	csrfHash, err := secret.Digest(rawCSRF)
	if err != nil {
		return domain.Session{}, ErrCSRF
	}
	user, err := s.users.GetForUpdate(ctx, userID)
	if err != nil {
		return domain.Session{}, fmt.Errorf("lock session management user: %w", authenticationError(err))
	}
	if err = user.Validate(); err != nil {
		return domain.Session{}, fmt.Errorf("validate session management user: %w", err)
	}
	if user.ID != userID || user.State != domain.UserActive {
		return domain.Session{}, ErrUnauthenticated
	}
	current, err := s.sessions.GetForUpdate(ctx, userID, callerID)
	if err != nil {
		return domain.Session{}, fmt.Errorf("lock session management caller: %w", authenticationError(err))
	}
	if err := current.Validate(); err != nil {
		return domain.Session{}, fmt.Errorf("validate session management caller: %w", err)
	}
	if current.ID != callerID || current.UserID != userID || !current.Active(time.Now().UTC()) {
		return domain.Session{}, ErrUnauthenticated
	}
	if subtle.ConstantTimeCompare(current.CSRFHash[:], csrfHash[:]) != 1 {
		return domain.Session{}, ErrCSRF
	}
	return current, nil
}
