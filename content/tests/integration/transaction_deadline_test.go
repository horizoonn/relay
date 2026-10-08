//go:build integration

package integration

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/horizoonn/relay/platform/pkg/httpmiddleware"
	"github.com/horizoonn/relay/platform/pkg/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestTransactionPoolDeadline(t *testing.T) {
	base, ctx := testPool(t)
	settings := base.Config()
	settings.MaxConns = 1
	settings.MinConns = 0
	pool, err := pgxpool.NewWithConfig(ctx, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	held, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	manager := postgres.NewTxManager(pool)
	handler := httpmiddleware.Deadline(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		err := manager.WithinTransaction(r.Context(), func(context.Context) error {
			t.Fatal("transaction started while the only connection was held")
			return nil
		})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error=%v", err)
		}
	}), 50*time.Millisecond)
	started := time.Now()
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(ctx, http.MethodPost, "/", nil))
	if time.Since(started) > time.Second {
		t.Fatal("pool wait exceeded request deadline")
	}
}
