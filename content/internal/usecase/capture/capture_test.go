package capture

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/content/internal/domain"
)

var testOwnerID = uuid.MustParse("00000000-0000-0000-0000-000000000001")

func TestCaptureURLReplay(t *testing.T) {
	t.Parallel()
	tx := newFakeTransactor()
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	service := testService(tx, &now)
	command := Command{
		OwnerID:        testOwnerID,
		IdempotencyKey: "first",
		SourceType:     domain.SourceURL,
		URL:            "HTTPS://EXAMPLE.COM/a",
		Keep:           true,
	}

	created, err := service.Capture(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if created.Outcome != OutcomeCreated || created.ItemID == uuid.Nil() {
		t.Fatalf("created result = %+v", created)
	}
	item := tx.items[created.ItemID]
	if item.Source().OriginalURL != command.URL ||
		item.Source().NormalizedURL != "https://example.com/a" || !item.Keep() {
		t.Fatalf("created item = %+v", item)
	}
	if titleErr := item.SetDisplayTitle("My title", now); titleErr != nil {
		t.Fatal(titleErr)
	}
	if reviewErr := item.SetReviewStatus(domain.ReviewDone, now); reviewErr != nil {
		t.Fatal(reviewErr)
	}
	tx.items[item.ID()] = item

	now = now.Add(time.Hour)
	reused, err := service.Capture(context.Background(), Command{
		OwnerID:        testOwnerID,
		IdempotencyKey: "second",
		SourceType:     domain.SourceURL,
		URL:            "https://example.com/a",
		Later:          true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if reused.Outcome != OutcomeReused || reused.ItemID != created.ItemID || len(tx.items) != 1 {
		t.Fatalf("reused result = %+v, item count = %d", reused, len(tx.items))
	}
	item = tx.items[created.ItemID]
	_, scheduled := item.LaterAt()
	if item.Source().OriginalURL != command.URL || item.DisplayTitle() != "My title" ||
		!item.Keep() || item.ReviewStatus() != domain.ReviewLater || !scheduled ||
		!item.LastCapturedAt().Equal(now) {
		t.Fatalf("reused item = %+v", item)
	}

	delete(tx.items, created.ItemID)
	now = now.Add(time.Hour)
	replay, err := service.Capture(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if replay != created || len(tx.items) != 0 {
		t.Fatalf("replay = %+v, item count = %d", replay, len(tx.items))
	}
}

func TestCaptureText(t *testing.T) {
	t.Parallel()
	tx := newFakeTransactor()
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	service := testService(tx, &now)
	command := Command{
		OwnerID:        testOwnerID,
		IdempotencyKey: "first",
		SourceType:     domain.SourceText,
		Text:           "  same text  ",
	}
	first, err := service.Capture(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	command.IdempotencyKey = "second key"
	second, err := service.Capture(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if first.Outcome != OutcomeCreated || second.Outcome != OutcomeCreated ||
		first.ItemID == second.ItemID || len(tx.items) != 2 {
		t.Fatalf("first = %+v, second = %+v, item count = %d", first, second, len(tx.items))
	}
	if tx.items[first.ItemID].Source().Text != command.Text {
		t.Fatal("text source was modified")
	}
}

func TestCaptureKeyConflict(t *testing.T) {
	t.Parallel()
	tx := newFakeTransactor()
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	service := testService(tx, &now)
	command := Command{
		OwnerID:        testOwnerID,
		IdempotencyKey: "same",
		SourceType:     domain.SourceURL,
		URL:            "HTTPS://EXAMPLE.COM",
	}
	first, err := service.Capture(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	command.URL = "https://example.com/"
	if _, err := service.Capture(context.Background(), command); !errors.Is(err, ErrIdempotencyKeyReused) {
		t.Fatalf("error = %v, want %v", err, ErrIdempotencyKeyReused)
	}
	if len(tx.items) != 1 || tx.items[first.ItemID].LastCapturedAt() != now {
		t.Fatal("conflicting command changed an item")
	}
}

func TestCaptureRollback(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name         string
		collision    bool
		failComplete bool
		wantErr      error
	}{
		{
			name:      "hash collision",
			collision: true,
			wantErr:   ErrURLHashCollision,
		},
		{
			name:         "receipt failure",
			failComplete: true,
			wantErr:      errFakeComplete,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tx := newFakeTransactor()
			tx.collision = tt.collision
			tx.failComplete = tt.failComplete
			now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
			service := testService(tx, &now)
			_, err := service.Capture(context.Background(), Command{
				OwnerID:        testOwnerID,
				IdempotencyKey: "key",
				SourceType:     domain.SourceURL,
				URL:            "https://example.com/",
			})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			if len(tx.items) != 0 || len(tx.receipts) != 0 {
				t.Fatalf("transaction committed: items=%d receipts=%d", len(tx.items), len(tx.receipts))
			}
		})
	}
}

func TestCaptureInvalidCommand(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		command Command
	}{
		{
			name: "missing owner",
			command: Command{
				IdempotencyKey: "key",
				SourceType:     domain.SourceText,
				Text:           "text",
			},
		},
		{
			name: "key with control",
			command: Command{
				OwnerID:        testOwnerID,
				IdempotencyKey: "bad\tkey",
				SourceType:     domain.SourceText,
				Text:           "text",
			},
		},
		{
			name: "two sources",
			command: Command{
				OwnerID:        testOwnerID,
				IdempotencyKey: "key",
				SourceType:     domain.SourceURL,
				URL:            "https://example.com",
				Text:           "text",
			},
		},
		{
			name: "invalid URL",
			command: Command{
				OwnerID:        testOwnerID,
				IdempotencyKey: "key",
				SourceType:     domain.SourceURL,
				URL:            "ftp://example.com",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tx := newFakeTransactor()
			now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
			_, err := testService(tx, &now).Capture(context.Background(), tt.command)
			if err == nil || tx.calls != 0 {
				t.Fatalf("error = %v, transactions = %d", err, tx.calls)
			}
		})
	}
}

var errFakeComplete = errors.New("complete failed")

type fakeTransactor struct {
	items        map[uuid.UUID]domain.Item
	receipts     map[string]IdempotencyRecord
	calls        int
	collision    bool
	failComplete bool
}

func newFakeTransactor() *fakeTransactor {
	return &fakeTransactor{
		items:    make(map[uuid.UUID]domain.Item),
		receipts: make(map[string]IdempotencyRecord),
	}
}

type fakeTxKey struct{}

func (f *fakeTransactor) WithinTransaction(
	ctx context.Context,
	fn func(context.Context) error,
) error {
	f.calls++
	tx := &fakeTransaction{
		items:        make(map[uuid.UUID]domain.Item),
		receipts:     make(map[string]IdempotencyRecord),
		collision:    f.collision,
		failComplete: f.failComplete,
	}
	for id, item := range f.items {
		tx.items[id] = item
	}
	for key, record := range f.receipts {
		tx.receipts[key] = record
	}
	if err := fn(context.WithValue(ctx, fakeTxKey{}, tx)); err != nil {
		return err
	}
	f.items, f.receipts = tx.items, tx.receipts
	return nil
}

func (f *fakeTransactor) transaction(ctx context.Context) *fakeTransaction {
	return ctx.Value(fakeTxKey{}).(*fakeTransaction)
}

func (f *fakeTransactor) FindByNormalizedURL(
	ctx context.Context,
	ownerID uuid.UUID,
	normalizedURL string,
) (domain.Item, error) {
	return f.transaction(ctx).FindByNormalizedURL(ctx, ownerID, normalizedURL)
}

func (f *fakeTransactor) Create(
	ctx context.Context,
	item domain.Item,
) (bool, error) {
	return f.transaction(ctx).Create(ctx, item)
}

func (f *fakeTransactor) Update(
	ctx context.Context,
	item domain.Item,
) error {
	return f.transaction(ctx).Update(ctx, item)
}

func (f *fakeTransactor) Claim(
	ctx context.Context,
	params ClaimParams,
) (IdempotencyRecord, bool, error) {
	return f.transaction(ctx).Claim(ctx, params)
}

func (f *fakeTransactor) Complete(
	ctx context.Context,
	params CompleteParams,
) error {
	return f.transaction(ctx).Complete(ctx, params)
}

type fakeTransaction struct {
	items        map[uuid.UUID]domain.Item
	receipts     map[string]IdempotencyRecord
	collision    bool
	failComplete bool
}

func (f *fakeTransaction) FindByNormalizedURL(
	_ context.Context,
	ownerID uuid.UUID,
	normalizedURL string,
) (domain.Item, error) {
	if f.collision {
		source, err := domain.NewURLSource("https://other.example/")
		if err != nil {
			return domain.Item{}, err
		}
		return domain.NewItem(uuid.MustParse("00000000-0000-0000-0000-000000000099"), ownerID, source,
			time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC))
	}
	hash := sha256.Sum256([]byte(normalizedURL))
	for _, item := range f.items {
		if item.OwnerID() == ownerID && item.Source().Type == domain.SourceURL &&
			sha256.Sum256([]byte(item.Source().NormalizedURL)) == hash {
			return item, nil
		}
	}
	return domain.Item{}, errors.New("item not found")
}

func (f *fakeTransaction) Create(
	_ context.Context,
	item domain.Item,
) (bool, error) {
	if f.collision {
		return false, nil
	}
	if item.Source().Type == domain.SourceURL {
		hash := sha256.Sum256([]byte(item.Source().NormalizedURL))
		for _, existing := range f.items {
			if existing.OwnerID() == item.OwnerID() && existing.Source().Type == domain.SourceURL &&
				sha256.Sum256([]byte(existing.Source().NormalizedURL)) == hash {
				return false, nil
			}
		}
	}
	f.items[item.ID()] = item
	return true, nil
}

func (f *fakeTransaction) Update(_ context.Context, item domain.Item) error {
	if _, ok := f.items[item.ID()]; !ok {
		return errors.New("item not found")
	}
	f.items[item.ID()] = item
	return nil
}

func (f *fakeTransaction) Claim(
	_ context.Context,
	params ClaimParams,
) (IdempotencyRecord, bool, error) {
	key := params.OwnerID.String() + ":" + params.Key
	if record, exists := f.receipts[key]; exists {
		return record, false, nil
	}
	f.receipts[key] = IdempotencyRecord{
		FingerprintVersion: params.FingerprintVersion,
		Fingerprint:        params.Fingerprint,
	}
	return IdempotencyRecord{}, true, nil
}

func (f *fakeTransaction) Complete(
	_ context.Context,
	params CompleteParams,
) error {
	if f.failComplete {
		return errFakeComplete
	}
	key := params.OwnerID.String() + ":" + params.Key
	record := f.receipts[key]
	record.ItemID, record.Outcome = params.ItemID, params.Outcome
	f.receipts[key] = record
	return nil
}

func testService(tx *fakeTransactor, now *time.Time) *Service {
	service := NewService(tx, tx, tx)
	service.now = func() time.Time { return *now }
	var sequence byte
	service.newID = func() uuid.UUID {
		sequence++
		var id uuid.UUID
		id[15] = sequence
		return id
	}
	return service
}
