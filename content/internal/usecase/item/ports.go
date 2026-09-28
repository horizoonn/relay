package item

import (
	"context"
	"uuid"

	"github.com/horizoonn/relay/content/internal/domain"
)

type Repository interface {
	Get(
		ctx context.Context,
		ownerID, itemID uuid.UUID,
	) (domain.Item, error)

	GetForUpdate(
		ctx context.Context,
		ownerID, itemID uuid.UUID,
	) (domain.Item, error)

	Patch(
		ctx context.Context,
		item domain.Item,
		fields PatchFields,
	) error

	Delete(
		ctx context.Context,
		ownerID, itemID uuid.UUID,
	) error
}

type PatchFields struct {
	Keep         bool
	ReviewStatus bool
	DisplayTitle bool
}

type Transactor interface {
	WithinTransaction(
		ctx context.Context,
		fn func(context.Context) error,
	) error
}
