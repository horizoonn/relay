package domain

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
	"uuid"
)

type ReviewStatus string

const (
	ReviewNone  ReviewStatus = "none"
	ReviewLater ReviewStatus = "later"
	ReviewDone  ReviewStatus = "done"
)

func (s ReviewStatus) valid() bool {
	return s == ReviewNone || s == ReviewLater || s == ReviewDone
}

type Item struct {
	state ItemState
}

type ItemState struct {
	ID             uuid.UUID
	OwnerID        uuid.UUID
	Source         Source
	DisplayTitle   string
	ReviewStatus   ReviewStatus
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LastCapturedAt time.Time
	KeptAt         *time.Time
	LaterAt        *time.Time
}

func RestoreItem(state ItemState) (Item, error) {
	if state.KeptAt != nil {
		keptAt := *state.KeptAt
		state.KeptAt = &keptAt
	}
	if state.LaterAt != nil {
		laterAt := *state.LaterAt
		state.LaterAt = &laterAt
	}
	i := Item{
		state: state,
	}
	if err := i.Validate(); err != nil {
		return Item{}, err
	}
	return i, nil
}

func NewItem(
	id, ownerID uuid.UUID,
	source Source,
	now time.Time,
) (Item, error) {
	i := Item{
		state: ItemState{
			ID:             id,
			OwnerID:        ownerID,
			Source:         source,
			ReviewStatus:   ReviewNone,
			CreatedAt:      now,
			UpdatedAt:      now,
			LastCapturedAt: now,
		},
	}
	if err := i.Validate(); err != nil {
		return Item{}, err
	}
	return i, nil
}

func (i Item) ID() uuid.UUID              { return i.state.ID }
func (i Item) OwnerID() uuid.UUID         { return i.state.OwnerID }
func (i Item) Source() Source             { return i.state.Source }
func (i Item) DisplayTitle() string       { return i.state.DisplayTitle }
func (i Item) ReviewStatus() ReviewStatus { return i.state.ReviewStatus }
func (i Item) CreatedAt() time.Time       { return i.state.CreatedAt }
func (i Item) UpdatedAt() time.Time       { return i.state.UpdatedAt }
func (i Item) LastCapturedAt() time.Time  { return i.state.LastCapturedAt }
func (i Item) Keep() bool                 { return i.state.KeptAt != nil }

func (i Item) KeptAt() (time.Time, bool) {
	if i.state.KeptAt == nil {
		return time.Time{}, false
	}
	return *i.state.KeptAt, true
}

func (i Item) LaterAt() (time.Time, bool) {
	if i.state.LaterAt == nil {
		return time.Time{}, false
	}
	return *i.state.LaterAt, true
}

func (i Item) Validate() error {
	if i.state.ID == uuid.Nil() || i.state.OwnerID == uuid.Nil() {
		return fmt.Errorf("%w: missing ID or owner ID", ErrInvalidItem)
	}
	if !i.state.Source.valid() {
		return fmt.Errorf("%w: invalid source", ErrInvalidItem)
	}
	if !i.state.ReviewStatus.valid() {
		return fmt.Errorf("%w: invalid review status", ErrInvalidItem)
	}
	if i.state.CreatedAt.IsZero() || i.state.UpdatedAt.IsZero() || i.state.LastCapturedAt.IsZero() {
		return fmt.Errorf("%w: missing timestamp", ErrInvalidItem)
	}
	if i.state.KeptAt != nil && i.state.KeptAt.IsZero() {
		return fmt.Errorf("%w: zero kept-at timestamp", ErrInvalidItem)
	}
	if (i.state.ReviewStatus == ReviewLater) != (i.state.LaterAt != nil) ||
		(i.state.LaterAt != nil && i.state.LaterAt.IsZero()) {
		return fmt.Errorf("%w: review status and later-at disagree", ErrInvalidItem)
	}
	if i.state.DisplayTitle != "" && !validTitle(i.state.DisplayTitle) {
		return fmt.Errorf("%w: invalid display title", ErrInvalidItem)
	}
	return nil
}

func (i *Item) SetKeep(keep bool, now time.Time) error {
	if (i.state.KeptAt != nil) == keep {
		return nil
	}
	if now.IsZero() {
		return ErrInvalidItem
	}
	if keep {
		i.state.KeptAt = &now
	} else {
		i.state.KeptAt = nil
	}
	i.state.UpdatedAt = now
	return nil
}

func (i *Item) SetReviewStatus(status ReviewStatus, now time.Time) error {
	if !status.valid() {
		return ErrInvalidReviewStatus
	}
	if i.state.ReviewStatus == status {
		return nil
	}
	if now.IsZero() {
		return ErrInvalidItem
	}
	if status == ReviewLater {
		i.state.LaterAt = &now
	} else {
		i.state.LaterAt = nil
	}
	i.state.ReviewStatus = status
	i.state.UpdatedAt = now
	return nil
}

func (i *Item) SetDisplayTitle(title string, now time.Time) error {
	if !validTitle(title) {
		return ErrInvalidDisplayTitle
	}
	if i.state.DisplayTitle == title {
		return nil
	}
	if now.IsZero() {
		return ErrInvalidItem
	}
	i.state.DisplayTitle = title
	i.state.UpdatedAt = now
	return nil
}

func (i *Item) ClearDisplayTitle(now time.Time) error {
	if i.state.DisplayTitle == "" {
		return nil
	}
	if now.IsZero() {
		return ErrInvalidItem
	}
	i.state.DisplayTitle = ""
	i.state.UpdatedAt = now
	return nil
}

func (i *Item) ApplyCapture(keep, later bool, now time.Time) error {
	if now.IsZero() {
		return ErrInvalidItem
	}
	previousUpdatedAt := i.state.UpdatedAt
	if keep {
		if err := i.SetKeep(true, now); err != nil {
			return err
		}
	}
	if later {
		if err := i.SetReviewStatus(ReviewLater, now); err != nil {
			return err
		}
	}
	if now.After(i.state.LastCapturedAt) {
		i.state.LastCapturedAt = now
	}
	if now.After(previousUpdatedAt) {
		i.state.UpdatedAt = now
	} else {
		i.state.UpdatedAt = previousUpdatedAt
	}
	return nil
}

func validTitle(title string) bool {
	return utf8.ValidString(title) && !strings.ContainsRune(title, '\x00') &&
		strings.TrimSpace(title) != "" && utf8.RuneCountInString(title) <= 256
}
