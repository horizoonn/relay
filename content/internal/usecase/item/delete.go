package item

import (
	"context"
	"fmt"
	"uuid"
)

func (s *Service) Delete(
	ctx context.Context,
	ownerID, itemID uuid.UUID,
) error {
	if ownerID == uuid.Nil() || itemID == uuid.Nil() {
		return ErrInvalidRequest
	}
	if err := s.repository.Delete(ctx, ownerID, itemID); err != nil {
		return fmt.Errorf("delete item: %w", err)
	}
	return nil
}
