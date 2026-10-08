//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/horizoonn/relay/platform/pkg/postgres"
	"github.com/jackc/pgx/v5"
)

// holdBeforeCommit keeps the first operation's writes and SQL locks uncommitted.
// The test releases it only after PostgreSQL reports the competing lock wait.
type holdBeforeCommit struct {
	*postgres.TxManager
	reached chan int32
	release <-chan struct{}
}

func (tx holdBeforeCommit) WithinTransaction(ctx context.Context, fn func(context.Context) error) error {
	return tx.TxManager.WithinTransaction(ctx, func(ctx context.Context) error {
		if err := fn(ctx); err != nil {
			return err
		}
		pid := int32(tx.Executor(ctx).(pgx.Tx).Conn().PgConn().PID())
		select {
		case tx.reached <- pid:
		case <-ctx.Done():
			return ctx.Err()
		}
		select {
		case <-tx.release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
}

func awaitHeldTransaction(t *testing.T, ctx context.Context, reached <-chan int32) int32 {
	t.Helper()
	select {
	case pid := <-reached:
		return pid
	case <-ctx.Done():
		t.Fatal("first operation did not reach its transaction barrier")
	}
	return 0
}
