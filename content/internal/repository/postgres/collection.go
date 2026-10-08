package repository

import (
	"context"
	"fmt"
	"uuid"

	"github.com/horizoonn/relay/content/internal/repository/postgres/model"
	"github.com/horizoonn/relay/content/internal/usecase"
	"github.com/horizoonn/relay/content/internal/usecase/collection"
)

func (r *Repository) ListRecent(
	ctx context.Context,
	params collection.ListParams,
) (collection.Page, error) {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()

	const query = `
		SELECT id, source_type, left(original_url, 513), left(source_text, 513), display_title,
			kept_at, review_status, created_at, updated_at, last_captured_at,
			last_captured_at AS sort_at
		FROM content.items
		WHERE owner_id = $1
			AND ($2::timestamptz IS NULL OR (last_captured_at, id) < ($2, $3))
		ORDER BY last_captured_at DESC, id DESC
		LIMIT $4
	`
	return r.listCollection(ctx, query, params)
}

func (r *Repository) ListLibrary(
	ctx context.Context,
	params collection.ListParams,
) (collection.Page, error) {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()

	const query = `
		SELECT id, source_type, left(original_url, 513), left(source_text, 513), display_title,
			kept_at, review_status, created_at, updated_at, last_captured_at,
			kept_at AS sort_at
		FROM content.items
		WHERE owner_id = $1 AND kept_at IS NOT NULL
			AND ($2::timestamptz IS NULL OR (kept_at, id) < ($2, $3))
		ORDER BY kept_at DESC, id DESC
		LIMIT $4
	`
	return r.listCollection(ctx, query, params)
}

func (r *Repository) ListLater(
	ctx context.Context,
	params collection.ListParams,
) (collection.Page, error) {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()

	const query = `
		SELECT id, source_type, left(original_url, 513), left(source_text, 513), display_title,
			kept_at, review_status, created_at, updated_at, last_captured_at,
			later_at AS sort_at
		FROM content.items
		WHERE owner_id = $1 AND review_status = 'later'
			AND ($2::timestamptz IS NULL OR (later_at, id) < ($2, $3))
		ORDER BY later_at DESC, id DESC
		LIMIT $4
	`
	return r.listCollection(ctx, query, params)
}

func (r *Repository) listCollection(
	ctx context.Context,
	query string,
	params collection.ListParams,
) (collection.Page, error) {
	var afterAt any
	afterID := uuid.Nil()
	if params.After != nil {
		afterAt, afterID = params.After.At, params.After.ID
	}
	rows, err := r.executor(ctx).Query(ctx, query, params.OwnerID, afterAt, afterID, params.Limit+1)
	if err != nil {
		return collection.Page{}, fmt.Errorf("query item collection: %w", err)
	}
	defer rows.Close()
	models := make([]model.Summary, 0, params.Limit+1)
	for rows.Next() {
		var summary model.Summary
		if err := summary.Scan(rows); err != nil {
			return collection.Page{}, fmt.Errorf("scan collection item: %w", err)
		}
		models = append(models, summary)
	}
	if err := rows.Err(); err != nil {
		return collection.Page{}, fmt.Errorf("iterate item collection: %w", err)
	}
	var next *collection.Anchor
	if len(models) > params.Limit {
		models = models[:params.Limit]
		last := models[len(models)-1]
		next = &collection.Anchor{
			At: last.SortAt,
			ID: last.ID,
		}
	}
	items := make([]usecase.ItemSummary, 0, len(models))
	for _, summary := range models {
		items = append(items, summary.ToSummary())
	}
	return collection.Page{
		Items: items,
		Next:  next,
	}, nil
}
