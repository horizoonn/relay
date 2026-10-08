//go:build integration

package integration

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/horizoonn/relay/platform/pkg/postgres"
	"github.com/jackc/pgx/v5/pgxpool"

	sessionrepo "github.com/horizoonn/relay/identity/internal/repository/postgres/session"
	userrepo "github.com/horizoonn/relay/identity/internal/repository/postgres/user"
	sessioncase "github.com/horizoonn/relay/identity/internal/usecase/session"
)

// The first service pauses before commit. The second reports its PostgreSQL
// backend so the test can observe it waiting for the first account lock.
type sessionLockRace struct {
	first, second       *sessioncase.Service
	pool                *pgxpool.Pool
	reached             <-chan struct{}
	heldPID, waitingPID <-chan uint32
	release             func()
}

func newSessionLockRace(t *testing.T, f lifecycleFixture) sessionLockRace {
	t.Helper()
	tx := postgres.NewTxManager(f.pool)
	users := userrepo.NewRepository(tx.Executor, 15*time.Second)
	sessions := sessionrepo.NewRepository(tx.Executor, 15*time.Second)
	reached, release := make(chan struct{}), make(chan struct{})
	heldPID, waitingPID := make(chan uint32, 1), make(chan uint32, 1)
	unblock := sync.OnceFunc(func() { close(release) })
	t.Cleanup(unblock)
	held := heldTransaction{TxManager: tx, reached: reached, backendPID: heldPID, release: release}
	first, err := sessioncase.NewService(users, sessions, held, f.issuer)
	if err != nil {
		t.Fatal(err)
	}
	observer := observingUserRepository{Repository: users, executor: tx.Executor, backendPID: waitingPID}
	second, err := sessioncase.NewService(observer, sessions, tx, f.issuer)
	if err != nil {
		t.Fatal(err)
	}
	return sessionLockRace{
		first: first, second: second, pool: f.pool, reached: reached,
		heldPID: heldPID, waitingPID: waitingPID, release: unblock,
	}
}

func (r sessionLockRace) awaitFirst(t *testing.T, ctx context.Context, done <-chan error) {
	t.Helper()
	select {
	case <-r.reached:
	case err := <-done:
		t.Fatalf("first operation returned before the commit barrier: %v", err)
	case <-ctx.Done():
		t.Fatal("first operation did not reach the commit barrier")
	}
}

func (r sessionLockRace) releaseAfterLockWait(t *testing.T, ctx context.Context) {
	t.Helper()
	var waiting, held uint32
	select {
	case waiting = <-r.waitingPID:
	case <-ctx.Done():
		t.Fatal("second operation did not attempt the account lock")
	}
	select {
	case held = <-r.heldPID:
	case <-ctx.Done():
		t.Fatal("first operation did not report its PostgreSQL backend")
	}
	waitForAccountLock(t, ctx, r.pool, waiting, held)
	r.release()
}
