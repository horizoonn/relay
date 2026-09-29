package repository

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/horizoonn/relay/content/internal/domain"
	"github.com/horizoonn/relay/content/internal/repository/postgres/model"
	itemusecase "github.com/horizoonn/relay/content/internal/usecase/item"
)

func (r *Repository) Patch(
	ctx context.Context,
	item domain.Item,
	fields itemusecase.PatchFields,
) error {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()

	const prefix = "UPDATE content.items SET "
	const suffix = " WHERE owner_id = $1 AND id = $2"

	if !fields.Keep && !fields.ReviewStatus && !fields.DisplayTitle {
		return itemusecase.ErrInvalidRequest
	}
	storedItem, err := model.ItemFromDomain(item)
	if err != nil {
		return err
	}
	args := []any{storedItem.OwnerID, storedItem.ID, storedItem.UpdatedAt}
	sets := []string{"updated_at = $3"}
	if fields.Keep {
		args = append(args, storedItem.KeptAt)
		sets = append(sets, fmt.Sprintf("kept_at = $%d", len(args)))
	}
	if fields.ReviewStatus {
		args = append(args, storedItem.ReviewStatus)
		sets = append(sets, fmt.Sprintf("review_status = $%d", len(args)))
		args = append(args, storedItem.LaterAt)
		sets = append(sets, fmt.Sprintf("later_at = $%d", len(args)))
	}
	if fields.DisplayTitle {
		args = append(args, storedItem.DisplayTitle)
		sets = append(sets, fmt.Sprintf("display_title = $%d", len(args)))
	}
	query := prefix + strings.Join(sets, ", ") + suffix
	tag, err := r.executor(ctx).Exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	return nil
}
