package model

import (
	"database/sql"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"

	"github.com/horizoonn/relay/content/internal/domain"
	"github.com/horizoonn/relay/content/internal/usecase"
)

type Summary struct {
	ID             uuid.UUID
	SourceType     string
	OriginalURL    sql.NullString
	SourceText     sql.NullString
	DisplayTitle   sql.NullString
	KeptAt         sql.NullTime
	ReviewStatus   string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LastCapturedAt time.Time
	SortAt         time.Time
}

func (summary *Summary) Scan(row pgx.Row) error {
	return row.Scan(&summary.ID, &summary.SourceType, &summary.OriginalURL, &summary.SourceText,
		&summary.DisplayTitle, &summary.KeptAt, &summary.ReviewStatus, &summary.CreatedAt, &summary.UpdatedAt,
		&summary.LastCapturedAt, &summary.SortAt)
}

func (summary Summary) ToSummary() usecase.ItemSummary {
	preview := summary.SourceText.String
	if summary.SourceType == string(domain.SourceURL) {
		preview = summary.OriginalURL.String
	}
	runes := []rune(preview)
	truncated := len(runes) > 512
	if truncated {
		preview = string(runes[:512])
	}
	return usecase.ItemSummary{
		ID:               summary.ID,
		SourceType:       domain.SourceType(summary.SourceType),
		DisplayTitle:     summary.DisplayTitle.String,
		Preview:          preview,
		PreviewTruncated: truncated,
		ReviewStatus:     domain.ReviewStatus(summary.ReviewStatus),
		Keep:             summary.KeptAt.Valid,
		CreatedAt:        summary.CreatedAt,
		UpdatedAt:        summary.UpdatedAt,
		LastCapturedAt:   summary.LastCapturedAt,
	}
}
