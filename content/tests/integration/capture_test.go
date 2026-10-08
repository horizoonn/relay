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

	"github.com/horizoonn/relay/content/internal/domain"
	contentrepo "github.com/horizoonn/relay/content/internal/repository/postgres"
	"github.com/horizoonn/relay/content/internal/usecase/capture"
	itemusecase "github.com/horizoonn/relay/content/internal/usecase/item"
)

func TestConcurrentURLCapture(t *testing.T) {
	pool, ctx := testPool(t)
	ownerID := uuid.New()
	cleanupOwner(t, pool, ownerID)
	tx := postgres.NewTxManager(pool)
	repo := contentrepo.NewRepository(tx.Executor, 5*time.Second)
	service := capture.NewService(repo, repo, tx)
	url := "https://example.com/concurrent/" + uuid.New().String()
	commands := []capture.Command{
		{
			OwnerID:        ownerID,
			IdempotencyKey: "keep",
			SourceType:     domain.SourceURL,
			URL:            url,
			Keep:           true,
		},
		{
			OwnerID:        ownerID,
			IdempotencyKey: "later",
			SourceType:     domain.SourceURL,
			URL:            url,
			Later:          true,
		},
	}
	reached, release := make(chan int32, 1), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	held := holdBeforeCommit{TxManager: tx, reached: reached, release: release}
	firstService := capture.NewService(repo, repo, held)
	type captureResult struct {
		value capture.Result
		err   error
	}
	firstDone, secondDone := make(chan captureResult, 1), make(chan captureResult, 1)
	go func() { result, err := firstService.Capture(ctx, commands[0]); firstDone <- captureResult{result, err} }()
	pid := awaitHeldTransaction(t, ctx, reached)
	go func() { result, err := service.Capture(ctx, commands[1]); secondDone <- captureResult{result, err} }()
	waitForLockWait(t, ctx, pool, pid)
	unblock()
	a, b := <-firstDone, <-secondDone
	results := []capture.Result{a.value, b.value}
	errs := []error{a.err, b.err}
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if results[0].ItemID != results[1].ItemID || results[0].Outcome == results[1].Outcome {
		t.Fatalf("concurrent results: %+v", results)
	}
	var count, receipts int
	var keep, later bool
	err := pool.QueryRow(ctx, `
		SELECT count(*), bool_or(kept_at IS NOT NULL), bool_or(review_status = 'later')
		FROM content.items WHERE owner_id = $1`, ownerID).Scan(&count, &keep, &later)
	if err != nil || count != 1 || !keep || !later {
		t.Fatalf("item count=%d keep=%t later=%t err=%v", count, keep, later, err)
	}
	const receiptCountQuery = `
		SELECT count(*)
		FROM content.idempotency_records
		WHERE owner_id = $1
	`
	if scanErr := pool.QueryRow(ctx, receiptCountQuery, ownerID).Scan(&receipts); scanErr != nil || receipts != 2 {
		t.Fatalf("receipt count=%d scanErr=%v", receipts, scanErr)
	}
	items := itemusecase.NewService(repo, tx)
	if deleteErr := items.Delete(ctx, ownerID, results[0].ItemID); deleteErr != nil {
		t.Fatal(deleteErr)
	}
	replay, err := service.Capture(ctx, commands[0])
	if err != nil || replay != results[0] {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	newCommand := commands[0]
	newCommand.IdempotencyKey = "after-delete"
	created, err := service.Capture(ctx, newCommand)
	if err != nil || created.Outcome != capture.OutcomeCreated || created.ItemID == results[0].ItemID {
		t.Fatalf("after delete=%+v err=%v", created, err)
	}
}

func TestExpiredCaptureKey(t *testing.T) {
	pool, ctx := testPool(t)
	ownerID := uuid.New()
	cleanupOwner(t, pool, ownerID)
	tx := postgres.NewTxManager(pool)
	repo := contentrepo.NewRepository(tx.Executor, 5*time.Second)
	old := capture.ClaimParams{
		OwnerID:            ownerID,
		Key:                "expired",
		FingerprintVersion: 1,
		Now:                time.Now().UTC().Add(-8 * 24 * time.Hour),
	}
	old.Fingerprint[0] = 1
	if err := tx.WithinTransaction(ctx, func(ctx context.Context) error {
		_, claimed, err := repo.Claim(ctx, old)
		if err != nil {
			return err
		}
		if !claimed {
			return errors.New("old key was not claimed")
		}
		return repo.Complete(ctx, capture.CompleteParams{
			OwnerID: ownerID,
			Key:     old.Key,
			ItemID:  uuid.New(),
			Outcome: capture.OutcomeCreated,
		})
	}); err != nil {
		t.Fatal(err)
	}
	newClaim := old
	newClaim.Now = time.Now().UTC()
	newClaim.Fingerprint[0] = 2
	if err := tx.WithinTransaction(ctx, func(ctx context.Context) error {
		_, claimed, err := repo.Claim(ctx, newClaim)
		if err != nil {
			return err
		}
		if !claimed {
			return errors.New("expired key was not claimed again")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
