package item

import (
	"context"
	"fmt"
	"uuid"

	"github.com/horizoonn/relay/content/internal/domain"
)

func (s *Service) Get(
	ctx context.Context,
	ownerID, itemID uuid.UUID,
) (domain.Item, error) {
	if ownerID == uuid.Nil() || itemID == uuid.Nil() {
		return domain.Item{}, ErrInvalidRequest
	}
	item, err := s.repository.Get(ctx, ownerID, itemID)
	if err != nil {
		return domain.Item{}, fmt.Errorf("get item: %w", err)
	}
	if item.OwnerID() != ownerID || item.ID() != itemID {
		return domain.Item{}, ErrItemNotFound
	}
	return item, nil
}
