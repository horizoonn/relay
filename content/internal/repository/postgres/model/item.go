package model

import (
	"crypto/sha256"
	"database/sql"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"

	"github.com/horizoonn/relay/content/internal/domain"
)

type Item struct {
	ID                uuid.UUID
	OwnerID           uuid.UUID
	SourceType        string
	OriginalURL       sql.NullString
	NormalizedURL     sql.NullString
	NormalizedURLHash []byte
	SourceText        sql.NullString
	DisplayTitle      sql.NullString
	ReviewStatus      string
	CreatedAt         time.Time
	UpdatedAt         time.Time
	LastCapturedAt    time.Time
	KeptAt            sql.NullTime
	LaterAt           sql.NullTime
}

func ItemFromDomain(item domain.Item) (Item, error) {
	if err := item.Validate(); err != nil {
		return Item{}, err
	}

	source := item.Source()
	model := Item{
		ID:             item.ID(),
		OwnerID:        item.OwnerID(),
		SourceType:     string(source.Type),
		ReviewStatus:   string(item.ReviewStatus()),
		CreatedAt:      item.CreatedAt(),
		UpdatedAt:      item.UpdatedAt(),
		LastCapturedAt: item.LastCapturedAt(),
	}
	if source.Type == domain.SourceURL {
		model.OriginalURL = sql.NullString{
			String: source.OriginalURL,
			Valid:  true,
		}
		model.NormalizedURL = sql.NullString{
			String: source.NormalizedURL,
			Valid:  true,
		}
		hash := sha256.Sum256([]byte(source.NormalizedURL))
		model.NormalizedURLHash = hash[:]
	} else {
		model.SourceText = sql.NullString{
			String: source.Text,
			Valid:  true,
		}
	}
	if item.DisplayTitle() != "" {
		model.DisplayTitle = sql.NullString{
			String: item.DisplayTitle(),
			Valid:  true,
		}
	}
	if keptAt, ok := item.KeptAt(); ok {
		model.KeptAt = sql.NullTime{
			Time:  keptAt,
			Valid: true,
		}
	}
	if laterAt, ok := item.LaterAt(); ok {
		model.LaterAt = sql.NullTime{
			Time:  laterAt,
			Valid: true,
		}
	}
	return model, nil
}

func (item *Item) Scan(row pgx.Row) error {
	return row.Scan(
		&item.ID, &item.OwnerID, &item.SourceType, &item.OriginalURL, &item.NormalizedURL,
		&item.SourceText, &item.DisplayTitle, &item.ReviewStatus, &item.CreatedAt,
		&item.UpdatedAt, &item.LastCapturedAt, &item.KeptAt, &item.LaterAt,
	)
}

func (item Item) ToDomain() (domain.Item, error) {
	state := domain.ItemState{
		ID:      item.ID,
		OwnerID: item.OwnerID,
		Source: domain.Source{
			Type:          domain.SourceType(item.SourceType),
			OriginalURL:   item.OriginalURL.String,
			NormalizedURL: item.NormalizedURL.String,
			Text:          item.SourceText.String,
		},
		DisplayTitle:   item.DisplayTitle.String,
		ReviewStatus:   domain.ReviewStatus(item.ReviewStatus),
		CreatedAt:      item.CreatedAt,
		UpdatedAt:      item.UpdatedAt,
		LastCapturedAt: item.LastCapturedAt,
	}
	if item.KeptAt.Valid {
		state.KeptAt = &item.KeptAt.Time
	}
	if item.LaterAt.Valid {
		state.LaterAt = &item.LaterAt.Time
	}
	return domain.RestoreItem(state)
}
