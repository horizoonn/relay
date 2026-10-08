package repository

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/horizoonn/relay/content/internal/usecase/capture"
)

func (r *Repository) Complete(
	ctx context.Context,
	params capture.CompleteParams,
) error {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()

	const query = `
		UPDATE content.idempotency_records
		SET item_id = $3, outcome = $4
		WHERE owner_id = $1 AND operation = 'capture' AND idempotency_key = $2
		AND item_id IS NULL
	`

	tag, err := r.executor(ctx).Exec(ctx,
		query,
		params.OwnerID,
		params.Key,
		params.ItemID,
		params.Outcome,
	)
	if err != nil {
		return fmt.Errorf("complete capture receipt: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	return nil
}
