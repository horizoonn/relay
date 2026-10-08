//go:build integration

package integration

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/platform/pkg/postgres"
	"github.com/jackc/pgx/v5"

	"github.com/horizoonn/relay/content/internal/domain"
	contentrepo "github.com/horizoonn/relay/content/internal/repository/postgres"
	"github.com/horizoonn/relay/content/internal/usecase/capture"
	itemusecase "github.com/horizoonn/relay/content/internal/usecase/item"
)

type heldItemRepository struct {
	*contentrepo.Repository
	executor postgres.ExecutorFunc
	reached  chan int32
	release  <-chan struct{}
}

func (r heldItemRepository) GetForUpdate(ctx context.Context, owner, id uuid.UUID) (domain.Item, error) {
	value, err := r.Repository.GetForUpdate(ctx, owner, id)
	if err != nil {
		return domain.Item{}, err
	}
	pid := int32(r.executor(ctx).(pgx.Tx).Conn().PgConn().PID())
	select {
	case r.reached <- pid:
	case <-ctx.Done():
		return domain.Item{}, ctx.Err()
	}
	select {
	case <-r.release:
		return value, nil
	case <-ctx.Done():
		return domain.Item{}, ctx.Err()
	}
}

func TestPatchOwnerScopeAndConcurrency(t *testing.T) {
	pool, ctx := testPool(t)
	owner, other := uuid.New(), uuid.New()
	cleanupOwner(t, pool, owner)
	tx := postgres.NewTxManager(pool)
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
	if _, getErr := items.Get(ctx, other, created.ItemID); !errors.Is(getErr, itemusecase.ErrItemNotFound) {
		t.Fatalf("foreign Get: %v", getErr)
	}
	if deleteErr := items.Delete(ctx, other, created.ItemID); !errors.Is(deleteErr, itemusecase.ErrItemNotFound) {
		t.Fatalf("foreign Delete: %v", deleteErr)
	}
	var beforeCaptured, beforeUpdated time.Time
	const timestampsQuery = `
		SELECT last_captured_at, updated_at
		FROM content.items
		WHERE id = $1
	`
	if scanErr := pool.QueryRow(ctx, timestampsQuery, created.ItemID).
		Scan(&beforeCaptured, &beforeUpdated); scanErr != nil {
		t.Fatal(scanErr)
	}

	reached, release := make(chan int32, 1), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	held := heldItemRepository{Repository: repo, executor: tx.Executor, reached: reached, release: release}
	keep, later := true, domain.ReviewLater
	firstCommand := itemusecase.PatchCommand{OwnerID: owner, ItemID: created.ItemID, Keep: &keep}
	firstDone := make(chan error, 1)
	go func() {
		_, patchErr := itemusecase.NewService(held, tx).Patch(ctx, firstCommand)
		firstDone <- patchErr
	}()
	pid := awaitHeldTransaction(t, ctx, reached)
	type patchResult struct {
		value domain.Item
		err   error
	}
	secondDone := make(chan patchResult, 1)
	go func() {
		value, patchErr := items.Patch(ctx, itemusecase.PatchCommand{OwnerID: owner, ItemID: created.ItemID, ReviewStatus: &later})
		secondDone <- patchResult{value, patchErr}
	}()
	waitForLockWait(t, ctx, pool, pid)
	unblock()
	if patchErr := <-firstDone; patchErr != nil {
		t.Fatal(patchErr)
	}
	second := <-secondDone
	if second.err != nil {
		t.Fatal(second.err)
	}
	if !second.value.Keep() || second.value.ReviewStatus() != domain.ReviewLater {
		t.Fatal("second PATCH did not observe the first committed change")
	}
	value, err := items.Get(ctx, owner, created.ItemID)
	if err != nil {
		t.Fatal(err)
	}
	if !value.Keep() || value.ReviewStatus() != domain.ReviewLater {
		t.Fatal("concurrent PATCH lost an independent field")
	}
	if !value.LastCapturedAt().Equal(beforeCaptured) {
		t.Fatal("PATCH changed last capture time")
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
	if _, err := items.Patch(ctx, firstCommand); err != nil {
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
