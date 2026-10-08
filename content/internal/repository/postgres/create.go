package repository

import (
	"context"
	"errors"
	"fmt"
	"uuid"

	"github.com/jackc/pgx/v5"

	"github.com/horizoonn/relay/content/internal/domain"
	"github.com/horizoonn/relay/content/internal/repository/postgres/model"
)

func (r *Repository) Create(
	ctx context.Context,
	item domain.Item,
) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()

	const query = `
		INSERT INTO content.items (
			id, owner_id, source_type, original_url, normalized_url, normalized_url_hash,
			source_text, display_title, review_status, created_at, updated_at,
			last_captured_at, kept_at, later_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		ON CONFLICT (owner_id, normalized_url_hash) WHERE source_type = 'url'
		DO NOTHING
		RETURNING id
	`

	storedItem, err := model.ItemFromDomain(item)
	if err != nil {
		return false, fmt.Errorf("prepare item insert: %w", err)
	}
	row := r.executor(ctx).QueryRow(ctx,
		query,
		storedItem.ID,
		storedItem.OwnerID,
		storedItem.SourceType,
		storedItem.OriginalURL,
		storedItem.NormalizedURL,
		storedItem.NormalizedURLHash,
		storedItem.SourceText,
		storedItem.DisplayTitle,
		storedItem.ReviewStatus,
		storedItem.CreatedAt,
		storedItem.UpdatedAt,
		storedItem.LastCapturedAt,
		storedItem.KeptAt,
		storedItem.LaterAt,
	)
	var createdID uuid.UUID
	err = row.Scan(&createdID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("execute item insert: %w", err)
	}
	return true, nil
}
