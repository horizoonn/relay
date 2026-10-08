package repository

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/horizoonn/relay/content/internal/domain"
	"github.com/horizoonn/relay/content/internal/repository/postgres/model"
)

func (r *Repository) Update(ctx context.Context, item domain.Item) error {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()

	const query = `
		UPDATE content.items
		SET review_status = $3, display_title = $4, updated_at = $5,
			last_captured_at = $6, kept_at = $7, later_at = $8
		WHERE owner_id = $1 AND id = $2
	`

	storedItem, err := model.ItemFromDomain(item)
	if err != nil {
		return fmt.Errorf("prepare item update: %w", err)
	}
	tag, err := r.executor(ctx).Exec(ctx,
		query,
		storedItem.OwnerID,
		storedItem.ID,
		storedItem.ReviewStatus,
		storedItem.DisplayTitle,
		storedItem.UpdatedAt,
		storedItem.LastCapturedAt,
		storedItem.KeptAt,
		storedItem.LaterAt,
	)
	if err != nil {
		return fmt.Errorf("update item: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	return nil
}
