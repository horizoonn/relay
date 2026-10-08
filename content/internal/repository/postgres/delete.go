package repository

import (
	"context"
	"errors"
	"fmt"
	"uuid"

	"github.com/jackc/pgx/v5"

	itemusecase "github.com/horizoonn/relay/content/internal/usecase/item"
)

func (r *Repository) Delete(
	ctx context.Context,
	ownerID, itemID uuid.UUID,
) error {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()

	const query = `
		DELETE FROM content.items
		WHERE owner_id = $1 AND id = $2
		RETURNING id
	`
	var deletedID uuid.UUID
	if err := r.executor(ctx).QueryRow(ctx, query, ownerID, itemID).Scan(&deletedID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return itemusecase.ErrItemNotFound
		}
		return fmt.Errorf("execute item deletion: %w", err)
	}
	return nil
}
