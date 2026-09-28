//go:build integration

package integration

import (
	"context"
	"os"
	"testing"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5/pgxpool"
)

func testPool(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("RELAY_CONTENT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("RELAY_CONTENT_TEST_DATABASE_URL must point to an isolated migrated Content database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		pool.Close()
	})
	if err := pool.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	return pool, ctx
}

func cleanupOwner(t *testing.T, pool *pgxpool.Pool, owner uuid.UUID) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := pool.Exec(ctx, `DELETE FROM content.idempotency_records WHERE owner_id = $1`, owner); err != nil {
			t.Errorf("delete receipts: %v", err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM content.items WHERE owner_id = $1`, owner); err != nil {
			t.Errorf("delete items: %v", err)
		}
	})
}
