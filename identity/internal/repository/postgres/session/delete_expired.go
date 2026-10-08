package session

import (
	"context"
	"fmt"
	"time"
)

func (r *Repository) DeleteExpired(
	ctx context.Context,
	before time.Time,
	limit int,
) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()

	const query = `
		WITH expired AS (
		    SELECT id FROM identity.sessions
		    WHERE expires_at <= $1
		    ORDER BY expires_at, id
		    FOR UPDATE SKIP LOCKED
		    LIMIT $2
		)
		DELETE FROM identity.sessions AS sessions
		USING expired WHERE sessions.id = expired.id
	`
	result, err := r.executor(ctx).Exec(ctx, query, before, limit)
	if err != nil {
		return 0, fmt.Errorf("delete expired sessions: %w", err)
	}
	return result.RowsAffected(), nil
}
