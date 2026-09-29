package collection

import (
	"context"
	"time"
	"uuid"

	"github.com/horizoonn/relay/content/internal/usecase"
)

type ListParams struct {
	OwnerID uuid.UUID
	Limit   int
	After   *Anchor
}

type Anchor struct {
	At time.Time
	ID uuid.UUID
}

type Page struct {
	Items []usecase.ItemSummary
	Next  *Anchor
}

type Reader interface {
	ListRecent(
		ctx context.Context,
		params ListParams,
	) (Page, error)

	ListLibrary(
		ctx context.Context,
		params ListParams,
	) (Page, error)

	ListLater(
		ctx context.Context,
		params ListParams,
	) (Page, error)
}
