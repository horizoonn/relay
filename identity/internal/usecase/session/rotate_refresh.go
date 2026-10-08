package session

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/horizoonn/relay/identity/internal/domain"
	"github.com/horizoonn/relay/identity/internal/secret"
)

func (s *Service) rotateRefresh(
	ctx context.Context,
	current domain.Session,
	credential domain.RefreshCredential,
	now time.Time,
) (RefreshResult, error) {
	if credential.Generation == math.MaxInt64 {
		return RefreshResult{}, domain.ErrInvalidRefreshCredential
	}
	raw, err := secret.Generate()
	if err != nil {
		return RefreshResult{}, fmt.Errorf("generate replacement refresh credential: %w", err)
	}
	nextHash, err := secret.Digest(raw)
	if err != nil {
		return RefreshResult{}, fmt.Errorf("digest replacement refresh credential: %w", err)
	}
	next := domain.RefreshCredential{
		TokenHash:  nextHash,
		SessionID:  current.ID,
		Generation: credential.Generation + 1,
		CreatedAt:  now,
		ExpiresAt:  credential.ExpiresAt,
	}
	if validateErr := next.Validate(); validateErr != nil {
		return RefreshResult{}, fmt.Errorf("validate replacement refresh credential: %w", validateErr)
	}
	if rotateErr := s.sessions.RotateRefreshCredential(ctx, credential.TokenHash, next); rotateErr != nil {
		return RefreshResult{}, fmt.Errorf("persist refresh rotation: %w", rotateErr)
	}
	access, err := s.issuer.Issue(current.UserID, current.ID, current.CSRFHash, current.ExpiresAt)
	if err != nil {
		return RefreshResult{}, fmt.Errorf("issue refreshed access token: %w", err)
	}
	return RefreshResult{
		UserID:           current.UserID,
		SessionID:        current.ID,
		SessionExpiresAt: current.ExpiresAt,
		AccessExpiresAt:  access.ExpiresAt,
		AccessToken:      access.Raw,
		RefreshToken:     raw,
	}, nil
}
