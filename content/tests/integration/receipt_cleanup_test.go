//go:build integration

package integration

import (
	"context"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/platform/pkg/postgres"

	contentrepo "github.com/horizoonn/relay/content/internal/repository/postgres"
)

func TestExpiredReceiptCleanup(t *testing.T) {
	pool, ctx := testPool(t)
	owner := uuid.New()
	cleanupOwner(t, pool, owner)
	now := time.Now().UTC()
	const insert = `
		INSERT INTO content.idempotency_records (
			owner_id, operation, idempotency_key, fingerprint_version,
			request_fingerprint, created_at, expires_at
		) VALUES ($1, 'capture', $2, 1, $3, $4, $5)
	`
	for _, receipt := range []struct {
		key       string
		expiresAt time.Time
	}{
		{
			key:       "expired-a",
			expiresAt: now.Add(-2 * time.Hour),
		},
		{
			key:       "expired-b",
			expiresAt: now.Add(-time.Hour),
		},
		{
			key:       "recently-expired",
			expiresAt: now.Add(-30 * time.Minute),
		},
		{
			key:       "active",
			expiresAt: now.Add(time.Hour),
		},
	} {
		if _, err := pool.Exec(
			ctx, insert, owner, receipt.key, make([]byte, 32),
			now.Add(-8*24*time.Hour), receipt.expiresAt,
		); err != nil {
			t.Fatal(err)
		}
	}
	repo := contentrepo.NewRepository(func(context.Context) postgres.Executor {
		return pool
	}, 5*time.Second)
	locked, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = locked.Rollback(context.Background()) }()
	const lockReceiptQuery = `
		SELECT 1
		FROM content.idempotency_records
		WHERE owner_id = $1 AND idempotency_key = 'expired-a'
		FOR UPDATE
	`
	if _, lockErr := locked.Exec(ctx, lockReceiptQuery, owner); lockErr != nil {
		t.Fatal(lockErr)
	}
	deleted, err := repo.DeleteExpiredReceipts(ctx, now.Add(-time.Hour), 1)
	if err != nil || deleted != 1 {
		t.Fatalf("cleanup with locked receipt: deleted = %d, err = %v", deleted, err)
	}
	var lockedCount int
	const lockedReceiptCountQuery = `
		SELECT count(*)
		FROM content.idempotency_records
		WHERE owner_id = $1 AND idempotency_key = 'expired-a'
	`
	if err := locked.QueryRow(ctx, lockedReceiptCountQuery, owner).Scan(&lockedCount); err != nil || lockedCount != 1 {
		t.Fatalf("locked receipt count = %d, err = %v", lockedCount, err)
	}
	if err := locked.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for _, want := range []int64{1, 0} {
		deleted, err := repo.DeleteExpiredReceipts(ctx, now.Add(-time.Hour), 1)
		if err != nil || deleted != want {
			t.Fatalf("deleted = %d, want %d, err = %v", deleted, want, err)
		}
	}
	var remaining int
	const remainingReceiptCountQuery = `
		SELECT count(*)
		FROM content.idempotency_records
		WHERE owner_id = $1 AND idempotency_key IN ('recently-expired', 'active')
	`
	if err := pool.QueryRow(ctx, remainingReceiptCountQuery, owner).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 2 {
		t.Fatalf("remaining protected receipts = %d, want 2", remaining)
	}
}
