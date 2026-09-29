package search

import (
	"context"
	"time"
	"uuid"

	"github.com/horizoonn/relay/content/internal/usecase"
)

type Params struct {
	OwnerID uuid.UUID
	Query   string
	Limit   int
	After   *Anchor
}

type MatchTier uint8

const (
	MatchTitleExact MatchTier = iota + 1
	MatchTitlePrefix
	MatchTitleSubstring
	MatchTextExact
	MatchTextPrefix
	MatchTextSubstring
	MatchURLExact
	MatchURLPrefix
	MatchURLSubstring
)

type Anchor struct {
	Tier           MatchTier
	LastCapturedAt time.Time
	ID             uuid.UUID
}

type Page struct {
	Items []usecase.ItemSummary
	Next  *Anchor
}

type Repository interface {
	Search(
		ctx context.Context,
		params Params,
	) (Page, error)
}
