package repository

import (
	"context"
	"fmt"
	"strings"
	"uuid"

	"github.com/horizoonn/relay/content/internal/repository/postgres/model"
	"github.com/horizoonn/relay/content/internal/usecase"
	"github.com/horizoonn/relay/content/internal/usecase/search"
)

func (r *Repository) Search(
	ctx context.Context,
	params search.Params,
) (search.Page, error) {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()

	const query = `
		WITH folded AS (
			SELECT id, source_type, original_url, source_text, display_title,
				kept_at, review_status, created_at, updated_at, last_captured_at,
				pg_catalog.casefold(display_title COLLATE pg_catalog."pg_unicode_fast") AS title_fold,
				pg_catalog.casefold((CASE source_type WHEN 'url' THEN original_url ELSE source_text END)
					COLLATE pg_catalog."pg_unicode_fast") AS source_fold
			FROM content.items
			WHERE owner_id = $1
		), ranked AS (
			SELECT *, CASE
				WHEN title_fold = pg_catalog.casefold($2::text COLLATE pg_catalog."pg_unicode_fast") THEN 1
				WHEN title_fold LIKE pg_catalog.casefold($3::text COLLATE pg_catalog."pg_unicode_fast") ESCAPE '\' THEN 2
				WHEN NOT $5
					AND title_fold LIKE pg_catalog.casefold($4::text COLLATE pg_catalog."pg_unicode_fast") ESCAPE '\' THEN 3
				WHEN NOT $5 AND source_type = 'text'
					AND source_fold = pg_catalog.casefold($2::text COLLATE pg_catalog."pg_unicode_fast") THEN 4
				WHEN NOT $5 AND source_type = 'text'
					AND source_fold LIKE pg_catalog.casefold($3::text COLLATE pg_catalog."pg_unicode_fast") ESCAPE '\' THEN 5
				WHEN NOT $5 AND source_type = 'text'
					AND source_fold LIKE pg_catalog.casefold($4::text COLLATE pg_catalog."pg_unicode_fast") ESCAPE '\' THEN 6
				WHEN NOT $5 AND source_type = 'url'
					AND source_fold = pg_catalog.casefold($2::text COLLATE pg_catalog."pg_unicode_fast") THEN 7
				WHEN NOT $5 AND source_type = 'url'
					AND source_fold LIKE pg_catalog.casefold($3::text COLLATE pg_catalog."pg_unicode_fast") ESCAPE '\' THEN 8
				WHEN NOT $5 AND source_type = 'url'
					AND source_fold LIKE pg_catalog.casefold($4::text COLLATE pg_catalog."pg_unicode_fast") ESCAPE '\' THEN 9
			END AS tier
			FROM folded
		)
		SELECT id, source_type, left(original_url, 513), left(source_text, 513), display_title,
			kept_at, review_status, created_at, updated_at, last_captured_at,
			last_captured_at AS sort_at, tier
		FROM ranked
		WHERE tier IS NOT NULL
			AND ($6::integer IS NULL OR tier > $6 OR
				(tier = $6 AND (last_captured_at, id) < ($7, $8)))
		ORDER BY tier ASC, last_captured_at DESC, id DESC
		LIMIT $9
	`

	escaped := escapeLike(params.Query)
	var afterTier any
	var afterAt any
	afterID := uuid.Nil()
	if params.After != nil {
		afterTier, afterAt, afterID = int(params.After.Tier), params.After.LastCapturedAt, params.After.ID
	}
	rows, err := r.executor(ctx).Query(ctx, query, params.OwnerID, params.Query,
		escaped+"%", "%"+escaped+"%", len([]rune(params.Query)) <= 2,
		afterTier, afterAt, afterID, params.Limit+1)
	if err != nil {
		return search.Page{}, err
	}
	defer rows.Close()
	models := make([]model.Search, 0, params.Limit+1)
	for rows.Next() {
		var result model.Search
		if err := result.Scan(rows); err != nil {
			return search.Page{}, err
		}
		models = append(models, result)
	}
	if err := rows.Err(); err != nil {
		return search.Page{}, err
	}
	var next *search.Anchor
	if len(models) > params.Limit {
		models = models[:params.Limit]
		last := models[len(models)-1]
		if last.Tier < int32(search.MatchTitleExact) || last.Tier > int32(search.MatchURLSubstring) {
			return search.Page{}, fmt.Errorf("invalid search rank %d", last.Tier)
		}
		next = &search.Anchor{
			Tier:           search.MatchTier(last.Tier),
			LastCapturedAt: last.LastCapturedAt,
			ID:             last.ID,
		}
	}
	items := make([]usecase.ItemSummary, 0, len(models))
	for _, result := range models {
		items = append(items, result.ToSummary())
	}
	return search.Page{
		Items: items,
		Next:  next,
	}, nil
}

func escapeLike(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `%`, `\%`)
	return strings.ReplaceAll(value, `_`, `\_`)
}
