package auth

import (
	"context"
	"fmt"
	"time"
	"uuid"

	"github.com/horizoonn/relay/identity/internal/domain"
	"github.com/horizoonn/relay/identity/internal/secret"
)

func (s *Service) completeLogin(
	ctx context.Context,
	userID uuid.UUID,
	verifiedHash, replacementHash string,
) (LoginResult, error) {
	refresh, err := secret.Generate()
	if err != nil {
		return LoginResult{}, fmt.Errorf("generate refresh credential: %w", err)
	}
	refreshHash, err := secret.Digest(refresh)
	if err != nil {
		return LoginResult{}, fmt.Errorf("digest refresh credential: %w", err)
	}
	csrf, err := secret.Generate()
	if err != nil {
		return LoginResult{}, fmt.Errorf("generate session CSRF: %w", err)
	}
	csrfHash, err := secret.Digest(csrf)
	if err != nil {
		return LoginResult{}, fmt.Errorf("digest session CSRF: %w", err)
	}

	var result LoginResult
	err = s.tx.WithinTransaction(ctx, func(ctx context.Context) error {
		current, loadErr := s.recheckPasswordCredentials(ctx, userID, verifiedHash)
		if loadErr != nil {
			return loadErr
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		session, sessionErr := domain.NewSession(current.ID, csrfHash, now, now.Add(domain.MaxSessionLifetime))
		if sessionErr != nil {
			return fmt.Errorf("create login session: %w", sessionErr)
		}
		if replacementHash != "" {
			if updateErr := s.users.RehashPassword(ctx, current.ID, replacementHash); updateErr != nil {
				return fmt.Errorf("persist replacement password hash: %w", updateErr)
			}
		}
		if createErr := s.sessions.Create(ctx, session, refreshHash); createErr != nil {
			return fmt.Errorf("persist login session: %w", createErr)
		}
		access, issueErr := s.issuer.Issue(current.ID, session.ID, csrfHash, session.ExpiresAt)
		if issueErr != nil {
			return fmt.Errorf("issue login access token: %w", issueErr)
		}
		result = LoginResult{
			UserID:           current.ID,
			SessionID:        session.ID,
			SessionExpiresAt: session.ExpiresAt,
			AccessToken:      access.Raw,
			AccessExpiresAt:  access.ExpiresAt,
			RefreshToken:     refresh,
			CSRFToken:        csrf,
		}
		return nil
	})
	if err != nil {
		return LoginResult{}, fmt.Errorf("complete login transaction: %w", err)
	}
	return result, nil
}
