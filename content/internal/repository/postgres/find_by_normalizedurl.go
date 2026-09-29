package repository

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"uuid"

	"github.com/jackc/pgx/v5"

	"github.com/horizoonn/relay/content/internal/domain"
	"github.com/horizoonn/relay/content/internal/repository/postgres/model"
	"github.com/horizoonn/relay/content/internal/usecase/capture"
)

func (r *Repository) FindByNormalizedURL(
	ctx context.Context,
	ownerID uuid.UUID,
	normalizedURL string,
) (domain.Item, error) {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()

	const query = `
		SELECT id, owner_id, source_type, original_url, normalized_url, source_text,
			display_title, review_status, created_at, updated_at, last_captured_at,
			kept_at, later_at
		FROM content.items
		WHERE owner_id = $1 AND source_type = 'url' AND normalized_url_hash = $2
		FOR UPDATE
	`

	hash := sha256.Sum256([]byte(normalizedURL))
	row := r.executor(ctx).QueryRow(ctx, query, ownerID, hash[:])
	var storedItem model.Item
	if err := storedItem.Scan(row); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Item{}, capture.ErrURLItemNotFound
		}
		return domain.Item{}, err
	}
	item, err := storedItem.ToDomain()
	if err != nil {
		return domain.Item{}, fmt.Errorf("restore URL item: %w", err)
	}
	return item, nil
}
