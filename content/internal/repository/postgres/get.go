package repository

import (
	"context"
	"errors"
	"fmt"
	"uuid"

	"github.com/jackc/pgx/v5"

	"github.com/horizoonn/relay/content/internal/domain"
	"github.com/horizoonn/relay/content/internal/repository/postgres/model"
	itemusecase "github.com/horizoonn/relay/content/internal/usecase/item"
)

func (r *Repository) Get(
	ctx context.Context,
	ownerID, itemID uuid.UUID,
) (domain.Item, error) {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()

	const query = `
		SELECT id, owner_id, source_type, original_url, normalized_url, source_text,
			display_title, review_status, created_at, updated_at, last_captured_at,
			kept_at, later_at
		FROM content.items
		WHERE owner_id = $1 AND id = $2
	`
	var storedItem model.Item
	if err := storedItem.Scan(r.executor(ctx).QueryRow(ctx, query, ownerID, itemID)); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Item{}, itemusecase.ErrItemNotFound
		}
		return domain.Item{}, fmt.Errorf("query item: %w", err)
	}
	item, err := storedItem.ToDomain()
	if err != nil {
		return domain.Item{}, fmt.Errorf("restore item: %w", err)
	}
	return item, nil
}

func (r *Repository) GetForUpdate(
	ctx context.Context,
	ownerID, itemID uuid.UUID,
) (domain.Item, error) {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()

	const query = `
		SELECT id, owner_id, source_type, original_url, normalized_url, source_text,
			display_title, review_status, created_at, updated_at, last_captured_at,
			kept_at, later_at
		FROM content.items
		WHERE owner_id = $1 AND id = $2
		FOR UPDATE
	`
	var storedItem model.Item
	if err := storedItem.Scan(r.executor(ctx).QueryRow(ctx, query, ownerID, itemID)); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Item{}, itemusecase.ErrItemNotFound
		}
		return domain.Item{}, fmt.Errorf("lock item: %w", err)
	}
	item, err := storedItem.ToDomain()
	if err != nil {
		return domain.Item{}, fmt.Errorf("restore item for update: %w", err)
	}
	return item, nil
}
