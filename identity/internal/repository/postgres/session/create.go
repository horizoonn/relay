package session

import (
	"context"
	"fmt"

	"github.com/horizoonn/relay/identity/internal/domain"
)

func (r *Repository) Create(
	ctx context.Context,
	session domain.Session,
	refreshHash [32]byte,
) error {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()

	const query = `
		WITH created AS (
			INSERT INTO identity.sessions
				(id, user_id, csrf_hash, created_at, authenticated_at, last_seen_at, expires_at, revoked_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			RETURNING id, created_at, expires_at
		)
		INSERT INTO identity.refresh_credentials
			(session_id, token_hash, generation, created_at, expires_at)
		SELECT id, $9, 0, created_at, expires_at FROM created
	`
	_, err := r.executor(ctx).Exec(
		ctx,
		query,
		session.ID,
		session.UserID,
		session.CSRFHash[:],
		session.CreatedAt,
		session.AuthenticatedAt,
		session.LastSeenAt,
		session.ExpiresAt,
		session.RevokedAt,
		refreshHash[:],
	)
	if err != nil {
		return fmt.Errorf("create session and refresh credential: %w", err)
	}
	return nil
}
