//go:build integration

package integration

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
	"uuid"

	platformpostgres "github.com/horizoonn/relay/platform/pkg/postgres"

	"github.com/horizoonn/relay/content/internal/domain"
	contentrepo "github.com/horizoonn/relay/content/internal/repository/postgres"
	"github.com/horizoonn/relay/content/internal/usecase/capture"
	itemusecase "github.com/horizoonn/relay/content/internal/usecase/item"
)

// The barrier lets both PATCH requests reach the repository before either reads the row.
type patchBarrierRepository struct {
	*contentrepo.Repository
	ready   chan struct{}
	release chan struct{}
}

func (r patchBarrierRepository) GetForUpdate(
	ctx context.Context,
	ownerID, itemID uuid.UUID,
) (domain.Item, error) {
	r.ready <- struct{}{}
	select {
	case <-r.release:
	case <-ctx.Done():
		return domain.Item{}, ctx.Err()
	}
	return r.Repository.GetForUpdate(ctx, ownerID, itemID)
}

func TestPatchOwnerScopeAndConcurrency(t *testing.T) {
	pool, ctx := testPool(t)
	owner, other := uuid.New(), uuid.New()
	cleanupOwner(t, pool, owner)
	tx := platformpostgres.NewTxManager(pool)
	repo := contentrepo.NewRepository(tx.Executor, 5*time.Second)
	created, err := capture.NewService(repo, repo, tx).Capture(ctx, capture.Command{
		OwnerID:        owner,
		IdempotencyKey: "create",
		SourceType:     domain.SourceText,
		Text:           "independent fields",
	})
	if err != nil {
		t.Fatal(err)
	}
	items := itemusecase.NewService(repo, tx)
	if _, err := items.Get(ctx, other, created.ItemID); !errors.Is(err, itemusecase.ErrItemNotFound) {
		t.Fatalf("foreign Get: %v", err)
	}
	if err := items.Delete(ctx, other, created.ItemID); !errors.Is(err, itemusecase.ErrItemNotFound) {
		t.Fatalf("foreign Delete: %v", err)
	}
	var beforeCaptured, beforeUpdated time.Time
	const timestampsQuery = `
		SELECT last_captured_at, updated_at
		FROM content.items
		WHERE id = $1
	`
	if err := pool.QueryRow(ctx, timestampsQuery, created.ItemID).
		Scan(&beforeCaptured, &beforeUpdated); err != nil {
		t.Fatal(err)
	}

	barrier := patchBarrierRepository{
		Repository: repo,
		ready:      make(chan struct{}, 2),
		release:    make(chan struct{}),
	}
	concurrentItems := itemusecase.NewService(barrier, tx)
	keep := true
	later := domain.ReviewLater
	commands := []itemusecase.PatchCommand{
		{
			OwnerID: owner,
			ItemID:  created.ItemID,
			Keep:    &keep,
		},
		{
			OwnerID:      owner,
			ItemID:       created.ItemID,
			ReviewStatus: &later,
		},
	}
	var wg sync.WaitGroup
	errs := make([]error, len(commands))
	for index := range commands {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			_, errs[index] = concurrentItems.Patch(ctx, commands[index])
		}(index)
	}
	for range commands {
		select {
		case <-barrier.ready:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	close(barrier.release)
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	value, err := items.Get(ctx, owner, created.ItemID)
	if err != nil {
		t.Fatal(err)
	}
	if !value.Keep() || value.ReviewStatus() != domain.ReviewLater || !value.LastCapturedAt().Equal(beforeCaptured) {
		t.Fatalf("concurrent PATCH lost an independent field: %+v", value)
	}
	var patchedUpdated time.Time
	const updatedAtQuery = `
		SELECT updated_at
		FROM content.items
		WHERE id = $1
	`
	if err := pool.QueryRow(ctx, updatedAtQuery, created.ItemID).Scan(&patchedUpdated); err != nil {
		t.Fatal(err)
	}
	if patchedUpdated.Before(beforeUpdated) {
		t.Fatalf("updated_at moved backwards: %s -> %s", beforeUpdated, patchedUpdated)
	}
	if _, err := items.Patch(ctx, commands[0]); err != nil {
		t.Fatal(err)
	}
	var noOpUpdated time.Time
	if err := pool.QueryRow(ctx, updatedAtQuery, created.ItemID).Scan(&noOpUpdated); err != nil {
		t.Fatal(err)
	}
	if !noOpUpdated.Equal(patchedUpdated) {
		t.Fatalf("no-op PATCH changed updated_at: %s -> %s", patchedUpdated, noOpUpdated)
	}
	if err := items.Delete(ctx, owner, created.ItemID); err != nil {
		t.Fatal(err)
	}
	if _, err := items.Get(ctx, owner, created.ItemID); !errors.Is(err, itemusecase.ErrItemNotFound) {
		t.Fatalf("Get after Delete: %v", err)
	}
	if err := items.Delete(ctx, owner, created.ItemID); !errors.Is(err, itemusecase.ErrItemNotFound) {
		t.Fatalf("repeated Delete: %v", err)
	}
}
