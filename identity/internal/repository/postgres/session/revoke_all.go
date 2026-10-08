package session

import (
	"context"
	"fmt"
	"time"
	"uuid"
)

func (r *Repository) RevokeAll(
	ctx context.Context,
	userID uuid.UUID,
	now time.Time,
) error {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()

	const query = `
		UPDATE identity.sessions SET revoked_at = $2
		WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $2
	`
	_, err := r.executor(ctx).Exec(ctx, query, userID, now)
	if err != nil {
		return fmt.Errorf("revoke user sessions: %w", err)
	}
	return nil
}
