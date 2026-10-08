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
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/horizoonn/relay/content/internal/domain"
	contentrepo "github.com/horizoonn/relay/content/internal/repository/postgres"
	"github.com/horizoonn/relay/content/internal/usecase/capture"
	itemusecase "github.com/horizoonn/relay/content/internal/usecase/item"
)

func TestDeleteConcurrentWithURLCapture(t *testing.T) {
	pool, ctx := testPool(t)
	owner := uuid.New()
	cleanupOwner(t, pool, owner)
	tx := postgres.NewTxManager(pool)
	repo := contentrepo.NewRepository(tx.Executor, 15*time.Second)
	captures := capture.NewService(repo, repo, tx)
	items := itemusecase.NewService(repo, tx)
	url := "https://example.com/delete-race/" + uuid.New().String()
	command := capture.Command{
		OwnerID:        owner,
		IdempotencyKey: "first",
		SourceType:     domain.SourceURL,
		URL:            url,
	}
	first, err := captures.Capture(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	deleted, finishDelete, deleteResult := deleteInsideOpenTransaction(ctx, tx, items, owner, first.ItemID)
	deletePID := awaitDelete(t, ctx, deleted, deleteResult)
	releaseDelete := sync.OnceFunc(func() { close(finishDelete) })
	t.Cleanup(func() {
		releaseDelete()
		for range deleteResult {
		}
	})
	command.IdempotencyKey = "after-delete"
	captureResult := make(chan struct {
		value capture.Result
		err   error
	}, 1)
	go func() {
		value, captureErr := captures.Capture(ctx, command)
		captureResult <- struct {
			value capture.Result
			err   error
		}{value, captureErr}
	}()
	waitForLockWait(t, ctx, pool, deletePID)
	releaseDelete()
	if err := <-deleteResult; err != nil {
		t.Fatal(err)
	}
	var second capture.Result
	select {
	case got := <-captureResult:
		if got.err != nil {
			t.Fatal(got.err)
		}
		second = got.value
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if second.Outcome != capture.OutcomeCreated || second.ItemID == first.ItemID {
		t.Fatalf("capture after concurrent delete: %+v, old ID %s", second, first.ItemID)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM content.items WHERE owner_id=$1 AND normalized_url=$2`,
		owner, mustNormalizedURL(t, url)).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("active matching URL items = %d, want 1", count)
	}
}

func TestDeleteConcurrentWithPatch(t *testing.T) {
	pool, ctx := testPool(t)
	owner := uuid.New()
	cleanupOwner(t, pool, owner)
	tx := postgres.NewTxManager(pool)
	repo := contentrepo.NewRepository(tx.Executor, 15*time.Second)
	captures := capture.NewService(repo, repo, tx)
	items := itemusecase.NewService(repo, tx)
	first, err := captures.Capture(ctx, capture.Command{
		OwnerID:        owner,
		IdempotencyKey: "first",
		SourceType:     domain.SourceText,
		Text:           "delete and patch",
	})
	if err != nil {
		t.Fatal(err)
	}
	deleted, finishDelete, deleteResult := deleteInsideOpenTransaction(ctx, tx, items, owner, first.ItemID)
	deletePID := awaitDelete(t, ctx, deleted, deleteResult)
	releaseDelete := sync.OnceFunc(func() { close(finishDelete) })
	t.Cleanup(func() {
		releaseDelete()
		for range deleteResult {
		}
	})
	patchResult := make(chan error, 1)
	go func() {
		keep := true
		_, patchErr := items.Patch(ctx, itemusecase.PatchCommand{
			OwnerID: owner,
			ItemID:  first.ItemID,
			Keep:    &keep,
		})
		patchResult <- patchErr
	}()
	waitForLockWait(t, ctx, pool, deletePID)
	releaseDelete()
	if err := <-deleteResult; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-patchResult:
		if !errors.Is(err, itemusecase.ErrItemNotFound) {
			t.Fatalf("PATCH after concurrent Delete: %v", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := items.Get(ctx, owner, first.ItemID); !errors.Is(err, itemusecase.ErrItemNotFound) {
		t.Fatalf("Get after Delete: %v", err)
	}
}

func deleteInsideOpenTransaction(
	ctx context.Context,
	tx *postgres.TxManager,
	items *itemusecase.Service,
	owner, itemID uuid.UUID,
) (<-chan int32, chan struct{}, <-chan error) {
	deleted := make(chan int32, 1)
	finish := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		defer close(result)
		result <- tx.WithinTransaction(ctx, func(txCtx context.Context) error {
			var pid int32
			if err := tx.Executor(txCtx).QueryRow(txCtx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				return err
			}
			if err := items.Delete(txCtx, owner, itemID); err != nil {
				return err
			}
			deleted <- pid
			select {
			case <-finish:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	return deleted, finish, result
}

func awaitDelete(
	t *testing.T,
	ctx context.Context,
	deleted <-chan int32,
	result <-chan error,
) int32 {
	t.Helper()
	select {
	case pid := <-deleted:
		return pid
	case err := <-result:
		t.Fatalf("Delete failed before lock could be held: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	return 0
}

func mustNormalizedURL(t *testing.T, raw string) string {
	t.Helper()
	normalized, err := domain.NormalizeURL(raw)
	if err != nil {
		t.Fatal(err)
	}
	return normalized
}

func waitForLockWait(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	deletePID int32,
) {
	t.Helper()
	deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		err := pool.QueryRow(deadline, `
			SELECT EXISTS (
				SELECT 1 FROM pg_stat_activity
				WHERE datname = current_database() AND usename = current_user
					AND wait_event_type = 'Lock'
					AND $1::integer = ANY(pg_blocking_pids(pid))
			)`, deletePID).Scan(&blocked)
		if err != nil {
			t.Fatalf("inspect PostgreSQL lock wait: %v", err)
		}
		if blocked {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.Done():
			t.Fatal("concurrent operation did not wait for the Delete transaction")
		}
	}
}
