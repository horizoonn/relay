package item

import (
	"context"
	"errors"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/content/internal/domain"
)

var (
	ownerID = uuid.MustParse("00000000-0000-0000-0000-000000000001")
	itemID  = uuid.MustParse("00000000-0000-0000-0000-000000000002")
)

func TestPatchAndNoOp(t *testing.T) {
	t.Parallel()
	store := newFakeStore(t)
	now := store.items[itemID].CreatedAt().Add(time.Hour)
	service := NewService(store, store)
	service.now = func() time.Time { return now }
	keep := true
	later := domain.ReviewLater
	title := "Read later"
	patch := PatchCommand{
		OwnerID:      ownerID,
		ItemID:       itemID,
		Keep:         &keep,
		ReviewStatus: &later,
		DisplayTitle: TitlePatch{
			Present: true,
			Value:   &title,
		},
	}
	got, err := service.Patch(context.Background(), patch)
	if err != nil {
		t.Fatal(err)
	}
	_, kept := got.KeptAt()
	_, scheduled := got.LaterAt()
	if !kept || !scheduled || got.ReviewStatus() != later || got.DisplayTitle() != title ||
		!got.UpdatedAt().Equal(now) || store.updates != 1 {
		t.Fatalf("patched item = %+v, updates = %d", got, store.updates)
	}
	if got.Source().Text != "original text" {
		t.Fatal("patch changed the source")
	}

	now = now.Add(time.Hour)
	again, err := service.Patch(context.Background(), patch)
	if err != nil {
		t.Fatal(err)
	}
	againKeptAt, againKept := again.KeptAt()
	keptAt, _ := got.KeptAt()
	againLaterAt, againLater := again.LaterAt()
	laterAt, _ := got.LaterAt()
	if store.updates != 1 || !again.UpdatedAt().Equal(got.UpdatedAt()) ||
		!againKept || !againKeptAt.Equal(keptAt) ||
		!againLater || !againLaterAt.Equal(laterAt) {
		t.Fatalf("no-op patch = %+v, updates = %d", again, store.updates)
	}
}

func TestPatchTitle(t *testing.T) {
	t.Parallel()
	store := newFakeStore(t)
	item := store.items[itemID]
	if err := item.SetDisplayTitle("Custom", item.CreatedAt()); err != nil {
		t.Fatal(err)
	}
	store.items[itemID] = item
	service := NewService(store, store)
	service.now = func() time.Time { return item.CreatedAt().Add(time.Hour) }

	keep := true
	got, err := service.Patch(context.Background(), PatchCommand{
		OwnerID: ownerID,
		ItemID:  itemID,
		Keep:    &keep,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.DisplayTitle() != "Custom" {
		t.Fatal("absent title cleared the override")
	}
	got, err = service.Patch(context.Background(), PatchCommand{
		OwnerID: ownerID,
		ItemID:  itemID,
		DisplayTitle: TitlePatch{
			Present: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.DisplayTitle() != "" || store.updates != 2 {
		t.Fatalf("clear title = %+v, updates = %d", got, store.updates)
	}
}

func TestPatchRollback(t *testing.T) {
	t.Parallel()
	store := newFakeStore(t)
	service := NewService(store, store)
	service.now = func() time.Time { return store.items[itemID].CreatedAt().Add(time.Hour) }
	keep := true
	invalidTitle := "   "
	_, err := service.Patch(context.Background(), PatchCommand{
		OwnerID: ownerID,
		ItemID:  itemID,
		Keep:    &keep,
		DisplayTitle: TitlePatch{
			Present: true,
			Value:   &invalidTitle,
		},
	})
	if !errors.Is(err, domain.ErrInvalidDisplayTitle) {
		t.Fatalf("error = %v", err)
	}
	if store.items[itemID].Keep() || store.updates != 0 {
		t.Fatal("invalid patch persisted a partial change")
	}
}

func TestPatchInvalidCommand(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		patch   PatchCommand
		wantErr error
	}{
		{
			name: "empty patch",
			patch: PatchCommand{
				OwnerID: ownerID,
				ItemID:  itemID,
			},
			wantErr: ErrInvalidRequest,
		},
		{
			name: "title value without presence",
			patch: PatchCommand{
				OwnerID: ownerID,
				ItemID:  itemID,
				DisplayTitle: TitlePatch{
					Value: ptr("title"),
				},
			},
			wantErr: ErrInvalidRequest,
		},
		{
			name: "invalid review status",
			patch: PatchCommand{
				OwnerID:      ownerID,
				ItemID:       itemID,
				ReviewStatus: reviewStatus("unknown"),
			},
			wantErr: domain.ErrInvalidReviewStatus,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := newFakeStore(t)
			service := NewService(store, store)
			_, err := service.Patch(context.Background(), tt.patch)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			if store.updates != 0 {
				t.Fatalf("invalid patch performed %d updates", store.updates)
			}
		})
	}
}

func ptr(value string) *string { return &value }

func reviewStatus(value domain.ReviewStatus) *domain.ReviewStatus { return &value }

func TestGetDeleteOwnerScope(t *testing.T) {
	t.Parallel()
	store := newFakeStore(t)
	service := NewService(store, store)
	otherOwner := uuid.New()
	if _, err := service.Get(context.Background(), otherOwner, itemID); !errors.Is(err, ErrItemNotFound) {
		t.Fatalf("foreign Get error = %v", err)
	}
	if err := service.Delete(context.Background(), otherOwner, itemID); !errors.Is(err, ErrItemNotFound) {
		t.Fatalf("foreign Delete error = %v", err)
	}
	if _, err := service.Get(context.Background(), ownerID, itemID); err != nil {
		t.Fatal(err)
	}
	if err := service.Delete(context.Background(), ownerID, itemID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Get(context.Background(), ownerID, itemID); !errors.Is(err, ErrItemNotFound) {
		t.Fatalf("deleted Get error = %v", err)
	}
	if err := service.Delete(context.Background(), ownerID, itemID); !errors.Is(err, ErrItemNotFound) {
		t.Fatalf("repeated Delete error = %v", err)
	}
}

type fakeStore struct {
	items   map[uuid.UUID]domain.Item
	updates int
}

func newFakeStore(t *testing.T) *fakeStore {
	t.Helper()
	source, err := domain.NewTextSource("original text")
	if err != nil {
		t.Fatal(err)
	}
	item, err := domain.NewItem(itemID, ownerID, source, time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return &fakeStore{
		items: map[uuid.UUID]domain.Item{itemID: item},
	}
}

type fakeTxKey struct{}

func (f *fakeStore) WithinTransaction(
	ctx context.Context,
	fn func(context.Context) error,
) error {
	tx := &fakeStore{
		items: make(map[uuid.UUID]domain.Item),
	}
	for id, item := range f.items {
		tx.items[id] = item
	}
	if err := fn(context.WithValue(ctx, fakeTxKey{}, tx)); err != nil {
		return err
	}
	f.items = tx.items
	f.updates += tx.updates
	return nil
}

func (f *fakeStore) Get(
	_ context.Context,
	ownerID,
	itemID uuid.UUID,
) (domain.Item, error) {
	item, found := f.items[itemID]
	if !found || item.OwnerID() != ownerID {
		return domain.Item{}, ErrItemNotFound
	}
	return item, nil
}

func (f *fakeStore) GetForUpdate(
	ctx context.Context,
	ownerID,
	itemID uuid.UUID,
) (domain.Item, error) {
	if tx, ok := ctx.Value(fakeTxKey{}).(*fakeStore); ok {
		return tx.Get(ctx, ownerID, itemID)
	}
	return f.Get(ctx, ownerID, itemID)
}

func (f *fakeStore) Patch(
	ctx context.Context,
	item domain.Item,
	_ PatchFields,
) error {
	if tx, ok := ctx.Value(fakeTxKey{}).(*fakeStore); ok {
		f = tx
	}
	if _, found := f.items[item.ID()]; !found {
		return ErrItemNotFound
	}
	f.items[item.ID()] = item
	f.updates++
	return nil
}

func (f *fakeStore) Delete(
	_ context.Context,
	ownerID,
	itemID uuid.UUID,
) error {
	item, found := f.items[itemID]
	if !found || item.OwnerID() != ownerID {
		return ErrItemNotFound
	}
	delete(f.items, itemID)
	return nil
}
