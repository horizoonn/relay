package item

import (
	"context"
	"fmt"
	"time"
	"uuid"

	"github.com/horizoonn/relay/content/internal/domain"
)

type TitlePatch struct {
	Present bool
	Value   *string
}

type PatchCommand struct {
	OwnerID      uuid.UUID
	ItemID       uuid.UUID
	Keep         *bool
	ReviewStatus *domain.ReviewStatus
	DisplayTitle TitlePatch
}

func (s *Service) Patch(
	ctx context.Context,
	command PatchCommand,
) (domain.Item, error) {
	if command.OwnerID == uuid.Nil() || command.ItemID == uuid.Nil() {
		return domain.Item{}, ErrInvalidRequest
	}
	emptyPatch := command.Keep == nil && command.ReviewStatus == nil && !command.DisplayTitle.Present
	invalidTitlePatch := !command.DisplayTitle.Present && command.DisplayTitle.Value != nil
	if emptyPatch || invalidTitlePatch {
		return domain.Item{}, ErrInvalidRequest
	}
	var result domain.Item
	err := s.transactor.WithinTransaction(ctx, func(ctx context.Context) error {
		var transactionErr error
		result, transactionErr = s.patchInTransaction(ctx, command)
		return transactionErr
	})
	if err != nil {
		return domain.Item{}, fmt.Errorf("patch item transaction: %w", err)
	}
	return result, nil
}

func (s *Service) patchInTransaction(
	ctx context.Context,
	command PatchCommand,
) (domain.Item, error) {
	item, err := s.repository.GetForUpdate(ctx, command.OwnerID, command.ItemID)
	if err != nil {
		return domain.Item{}, fmt.Errorf("get item for patch: %w", err)
	}
	if item.OwnerID() != command.OwnerID || item.ID() != command.ItemID {
		return domain.Item{}, ErrItemNotFound
	}
	now := s.now().UTC()
	if now.IsZero() {
		return domain.Item{}, fmt.Errorf("%w: missing patch time", ErrInvalidRequest)
	}
	changed := patchChanges(item, command)
	if applyErr := applyPatch(&item, command, now); applyErr != nil {
		return domain.Item{}, applyErr
	}
	if changed {
		fields := PatchFields{
			Keep:         command.Keep != nil,
			ReviewStatus: command.ReviewStatus != nil,
			DisplayTitle: command.DisplayTitle.Present,
		}
		if err := s.repository.Patch(ctx, item, fields); err != nil {
			return domain.Item{}, fmt.Errorf("update item: %w", err)
		}
	}
	return item, nil
}

func applyPatch(item *domain.Item, command PatchCommand, now time.Time) error {
	if command.Keep != nil {
		if err := item.SetKeep(*command.Keep, now); err != nil {
			return err
		}
	}
	if command.ReviewStatus != nil {
		if err := item.SetReviewStatus(*command.ReviewStatus, now); err != nil {
			return err
		}
	}
	if command.DisplayTitle.Present {
		if command.DisplayTitle.Value == nil {
			return item.ClearDisplayTitle(now)
		}
		return item.SetDisplayTitle(*command.DisplayTitle.Value, now)
	}
	return nil
}

func patchChanges(item domain.Item, command PatchCommand) bool {
	if command.Keep != nil && item.Keep() != *command.Keep {
		return true
	}
	if command.ReviewStatus != nil && item.ReviewStatus() != *command.ReviewStatus {
		return true
	}
	if command.DisplayTitle.Present {
		if command.DisplayTitle.Value == nil {
			return item.DisplayTitle() != ""
		}
		return item.DisplayTitle() != *command.DisplayTitle.Value
	}
	return false
}
