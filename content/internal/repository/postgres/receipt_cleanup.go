package repository

import (
	"context"
	"time"
)

func (r *Repository) DeleteExpiredReceipts(
	ctx context.Context,
	before time.Time,
	limit int,
) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()

	const query = `
		WITH expired AS (
			SELECT records.ctid
			FROM content.idempotency_records AS records
			WHERE records.expires_at <= $1
			ORDER BY records.expires_at
			FOR UPDATE SKIP LOCKED
			LIMIT $2
		)
		DELETE FROM content.idempotency_records AS records
		USING expired
		WHERE records.ctid = expired.ctid
	`
	result, err := r.executor(ctx).Exec(ctx, query, before, limit)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}
