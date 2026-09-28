package usecase

import (
	"time"
	"uuid"

	"github.com/horizoonn/relay/content/internal/domain"
)

type ItemSummary struct {
	ID               uuid.UUID
	SourceType       domain.SourceType
	DisplayTitle     string
	Preview          string
	PreviewTruncated bool
	Keep             bool
	ReviewStatus     domain.ReviewStatus
	CreatedAt        time.Time
	UpdatedAt        time.Time
	LastCapturedAt   time.Time
}
