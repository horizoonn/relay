package session

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/horizoonn/relay/identity/internal/domain"
	"github.com/horizoonn/relay/identity/internal/secret"
)

func (s *Service) Logout(ctx context.Context, rawRefresh, rawCSRF string) error {
	hash, err := secret.Digest(rawRefresh)
	if err != nil {
		return nil //nolint:nilerr // An absent/malformed credential still permits clearing cookies after Origin validation.
	}
	csrfHash, err := secret.Digest(rawCSRF)
	if err != nil {
		return ErrCSRF
	}
	initial, err := s.sessions.GetByRefreshHash(ctx, hash)
	if errors.Is(err, domain.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("load logout session: %w", err)
	}
	err = s.tx.WithinTransaction(ctx, func(ctx context.Context) error {
		_, current, lockErr := s.lockSession(ctx, initial)
		if lockErr != nil {
			return lockErr
		}
		if subtle.ConstantTimeCompare(current.CSRFHash[:], csrfHash[:]) != 1 {
			return ErrCSRF
		}
		if current.RevokedAt != nil {
			return nil
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		if now.Before(current.CreatedAt) {
			return ErrUnauthenticated
		}
		if revokeErr := s.sessions.Revoke(ctx, current.UserID, current.ID, now); revokeErr != nil {
			return fmt.Errorf("persist logout revocation: %w", revokeErr)
		}
		return nil
	})
	if errors.Is(err, ErrUnauthenticated) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("logout session transaction: %w", err)
	}
	return nil
}
