package model

import "github.com/jackc/pgx/v5"

type Search struct {
	Summary
	Tier int32
}

func (result *Search) Scan(row pgx.Row) error {
	return row.Scan(&result.ID, &result.SourceType, &result.OriginalURL, &result.SourceText,
		&result.DisplayTitle, &result.KeptAt, &result.ReviewStatus, &result.CreatedAt,
		&result.UpdatedAt, &result.LastCapturedAt, &result.SortAt, &result.Tier)
}
