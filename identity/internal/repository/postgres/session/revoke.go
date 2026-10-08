package session

import (
	"context"
	"fmt"
	"time"
	"uuid"

	"github.com/horizoonn/relay/identity/internal/domain"
)

func (r *Repository) Revoke(
	ctx context.Context,
	userID, sessionID uuid.UUID,
	now time.Time,
) error {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()

	const query = `
		UPDATE identity.sessions SET revoked_at = COALESCE(revoked_at, $3)
		WHERE user_id = $1 AND id = $2
	`
	result, err := r.executor(ctx).Exec(ctx, query, userID, sessionID, now)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}
