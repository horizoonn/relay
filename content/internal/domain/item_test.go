package domain_test

import (
	"errors"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/content/internal/domain"
)

func newItem(t *testing.T) domain.Item {
	t.Helper()
	source, err := domain.NewTextSource("original text")
	if err != nil {
		t.Fatal(err)
	}
	item, err := domain.NewItem(
		uuid.MustParse("00000000-0000-0000-0000-000000000002"),
		uuid.MustParse("00000000-0000-0000-0000-000000000001"),
		source,
		time.Date(2026, time.September, 23, 12, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	return item
}

func TestRestoreItemValidatesAndOwnsState(t *testing.T) {
	t.Parallel()
	original := newItem(t)
	keptAt := original.CreatedAt().Add(time.Hour)
	laterAt := keptAt.Add(time.Hour)
	state := domain.ItemState{
		ID:             original.ID(),
		OwnerID:        original.OwnerID(),
		Source:         original.Source(),
		ReviewStatus:   domain.ReviewLater,
		CreatedAt:      original.CreatedAt(),
		UpdatedAt:      laterAt,
		LastCapturedAt: original.LastCapturedAt(),
		KeptAt:         &keptAt,
		LaterAt:        &laterAt,
	}
	item, err := domain.RestoreItem(state)
	if err != nil {
		t.Fatal(err)
	}
	state.OwnerID = uuid.Nil()
	keptAt = keptAt.Add(time.Hour)
	laterAt = laterAt.Add(time.Hour)
	if item.OwnerID() != original.OwnerID() || item.ReviewStatus() != domain.ReviewLater {
		t.Fatal("restored Item changed after its input state was modified")
	}
	if got, ok := item.KeptAt(); !ok || !got.Equal(original.CreatedAt().Add(time.Hour)) {
		t.Fatal("restored Keep timestamp changed after its input was modified")
	}
	if got, ok := item.LaterAt(); !ok || !got.Equal(original.CreatedAt().Add(2*time.Hour)) {
		t.Fatal("restored Later timestamp changed after its input was modified")
	}
	state.ID = uuid.Nil()
	if _, err := domain.RestoreItem(state); !errors.Is(err, domain.ErrInvalidItem) {
		t.Fatalf("invalid state error = %v, want %v", err, domain.ErrInvalidItem)
	}
}

func TestItemKeepLater(t *testing.T) {
	t.Parallel()
	item := newItem(t)
	created := item.CreatedAt()
	kept := created.Add(time.Hour)
	later := kept.Add(time.Hour)
	if err := item.SetKeep(true, kept); err != nil {
		t.Fatal(err)
	}
	if err := item.SetReviewStatus(domain.ReviewLater, later); err != nil {
		t.Fatal(err)
	}
	if err := item.SetKeep(false, later.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if item.Keep() || item.ReviewStatus() != domain.ReviewLater {
		t.Fatalf("keep=%t review=%q; want false/later", item.Keep(), item.ReviewStatus())
	}
	if got, ok := item.LaterAt(); !ok || !got.Equal(later) {
		t.Fatalf("laterAt=%s present=%t; want %s", got, ok, later)
	}
	if !item.LastCapturedAt().Equal(created) {
		t.Fatal("Keep/Later mutation changed LastCapturedAt")
	}
	if err := item.SetReviewStatus(domain.ReviewDone, later.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, ok := item.LaterAt(); ok || item.ReviewStatus() != domain.ReviewDone {
		t.Fatal("Done must clear LaterAt without deleting the Item")
	}
	if err := item.Validate(); err != nil {
		t.Fatalf("valid Item rejected: %v", err)
	}
}

func TestItemNoOp(t *testing.T) {
	t.Parallel()
	item := newItem(t)
	created := item.CreatedAt()
	first := created.Add(time.Hour)
	if err := item.SetKeep(true, first); err != nil {
		t.Fatal(err)
	}
	if err := item.SetKeep(true, first.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got, ok := item.KeptAt(); !ok || !got.Equal(first) {
		t.Fatalf("keptAt=%s present=%t; want %s", got, ok, first)
	}
	if !item.UpdatedAt().Equal(first) {
		t.Fatal("no-op Keep changed UpdatedAt")
	}
	if err := item.SetDisplayTitle("My title", first.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	updated := item.UpdatedAt()
	if err := item.SetDisplayTitle("My title", updated.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := item.ClearDisplayTitle(updated.Add(2 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	cleared := item.UpdatedAt()
	if err := item.ClearDisplayTitle(cleared.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if item.DisplayTitle() != "" || !item.UpdatedAt().Equal(cleared) || !item.LastCapturedAt().Equal(created) {
		t.Fatal("title no-op or clear changed unrelated timestamps")
	}
}

func TestApplyCaptureTimestamp(t *testing.T) {
	t.Parallel()
	item := newItem(t)
	newer := item.CreatedAt().Add(2 * time.Hour)
	if err := item.ApplyCapture(true, true, newer); err != nil {
		t.Fatal(err)
	}
	if err := item.ApplyCapture(false, false, item.CreatedAt().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if !item.LastCapturedAt().Equal(newer) || !item.UpdatedAt().Equal(newer) ||
		!item.Keep() || item.ReviewStatus() != domain.ReviewLater {
		t.Fatal("older Capture moved timestamps backward or removed context")
	}
}

func TestItemInvalidMutation(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		mutate  func(*domain.Item) error
		wantErr error
	}{
		{
			name: "invalid status",
			mutate: func(item *domain.Item) error {
				return item.SetReviewStatus("unknown", time.Date(2026, 9, 23, 13, 0, 0, 0, time.UTC))
			},
			wantErr: domain.ErrInvalidReviewStatus,
		},
		{
			name: "blank title",
			mutate: func(item *domain.Item) error {
				return item.SetDisplayTitle(" \t ", time.Date(2026, 9, 23, 13, 0, 0, 0, time.UTC))
			},
			wantErr: domain.ErrInvalidDisplayTitle,
		},
		{
			name: "NUL in title",
			mutate: func(item *domain.Item) error {
				return item.SetDisplayTitle("a\x00b", item.CreatedAt())
			},
			wantErr: domain.ErrInvalidDisplayTitle,
		},
		{
			name: "zero keep time",
			mutate: func(item *domain.Item) error {
				return item.SetKeep(true, time.Time{})
			},
			wantErr: domain.ErrInvalidItem,
		},
		{
			name: "zero capture time",
			mutate: func(item *domain.Item) error {
				return item.ApplyCapture(true, true, time.Time{})
			},
			wantErr: domain.ErrInvalidItem,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			item := newItem(t)
			before := item
			if err := tt.mutate(&item); !errors.Is(err, tt.wantErr) {
				t.Fatalf("error=%v; want %v", err, tt.wantErr)
			}
			if item != before {
				t.Fatal("invalid mutation changed Item")
			}
		})
	}
}
