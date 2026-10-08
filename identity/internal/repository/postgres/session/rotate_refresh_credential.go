package session

import (
	"context"
	"fmt"

	"github.com/horizoonn/relay/identity/internal/domain"
)

func (r *Repository) RotateRefreshCredential(
	ctx context.Context,
	previousHash [32]byte,
	next domain.RefreshCredential,
) error {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()

	const query = `
		WITH consumed AS (
			UPDATE identity.refresh_credentials SET used_at = $4
			WHERE token_hash = $1 AND session_id = $2 AND used_at IS NULL
			RETURNING session_id
		), created AS (
			INSERT INTO identity.refresh_credentials
				(token_hash, session_id, generation, created_at, expires_at)
			SELECT $3, session_id, $5, $4, $6 FROM consumed
			RETURNING session_id
		)
		UPDATE identity.sessions SET last_seen_at = GREATEST(last_seen_at, $4)
		WHERE id IN (SELECT session_id FROM created)
	`
	result, err := r.executor(ctx).Exec(ctx, query, previousHash[:], next.SessionID,
		next.TokenHash[:], next.CreatedAt, next.Generation, next.ExpiresAt)
	if err != nil {
		return fmt.Errorf("rotate refresh credential: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}
