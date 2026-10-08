//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/platform/pkg/postgres"
	"github.com/jackc/pgx/v5"

	"github.com/horizoonn/relay/identity/internal/domain"
	sessionrepo "github.com/horizoonn/relay/identity/internal/repository/postgres/session"
	userrepo "github.com/horizoonn/relay/identity/internal/repository/postgres/user"
	"github.com/horizoonn/relay/identity/internal/secret"
	sessioncase "github.com/horizoonn/relay/identity/internal/usecase/session"
)

func TestRefreshTransactionFailure(t *testing.T) {
	f, ctx := lifecycle(t)
	tx := postgres.NewTxManager(f.pool)
	rejected := errors.New("transaction rejected after callback")
	service, err := sessioncase.NewService(userrepo.NewRepository(tx.Executor, time.Second),
		sessionrepo.NewRepository(tx.Executor, time.Second), abortAfterCallback{
			TxManager: tx,
			err:       rejected,
		}, f.issuer)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Refresh(ctx, f.rawRefresh, f.rawCSRF)
	if !errors.Is(err, rejected) || result != (sessioncase.RefreshResult{}) {
		t.Fatal("transaction failure returned signed credentials")
	}
	hash, err := secret.Digest(f.rawRefresh)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := f.sessions.GetRefreshCredential(ctx, hash)
	if err != nil || credential.UsedAt != nil {
		t.Fatal("aborted rotation consumed its credential")
	}
	current, err := f.sessions.Get(ctx, f.current.UserID, f.current.ID)
	if err != nil || !current.LastSeenAt.Equal(f.current.LastSeenAt) {
		t.Fatal("aborted rotation changed activity")
	}
}

type observingUserRepository struct {
	*userrepo.Repository
	executor   postgres.ExecutorFunc
	backendPID chan uint32
}

func (r observingUserRepository) GetForUpdate(ctx context.Context, id uuid.UUID) (domain.User, error) {
	tx, ok := r.executor(ctx).(pgx.Tx)
	if !ok {
		return domain.User{}, errors.New("account lock must use the refresh transaction")
	}
	r.backendPID <- tx.Conn().PgConn().PID()
	return r.Repository.GetForUpdate(ctx, id)
}

func TestRefreshRechecksAccountAfterWaitingForLock(t *testing.T) {
	f, ctx := lifecycle(t)
	tx := postgres.NewTxManager(f.pool)
	backendPID := make(chan uint32, 1)
	users := observingUserRepository{
		Repository: userrepo.NewRepository(tx.Executor, 5*time.Second),
		executor:   tx.Executor,
		backendPID: backendPID,
	}
	service, err := sessioncase.NewService(users, sessionrepo.NewRepository(tx.Executor, 5*time.Second), tx, f.issuer)
	if err != nil {
		t.Fatal(err)
	}
	blocker, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(context.WithoutCancel(ctx)) }()
	if _, updateErr := blocker.Exec(
		ctx,
		`UPDATE identity.users SET state='disabled' WHERE id=$1`,
		f.current.UserID,
	); updateErr != nil {
		t.Fatal(updateErr)
	}
	finished := make(chan error, 1)
	go func() {
		_, refreshErr := service.Refresh(ctx, f.rawRefresh, f.rawCSRF)
		finished <- refreshErr
	}()
	var refreshPID uint32
	select {
	case refreshPID = <-backendPID:
	case <-ctx.Done():
		t.Fatal("refresh never attempted the account lock")
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	const waitingForBlocker = `
        SELECT EXISTS (
            SELECT 1 FROM pg_stat_activity
            WHERE pid = $1 AND wait_event_type = 'Lock'
                AND $2 = ANY(pg_blocking_pids(pid))
        )
    `
	for {
		var waiting bool
		if observeErr := f.pool.QueryRow(ctx, waitingForBlocker, refreshPID,
			blocker.Conn().PgConn().PID()).Scan(&waiting); observeErr != nil {
			t.Fatal(observeErr)
		}
		if waiting {
			break
		}
		select {
		case <-finished:
			t.Fatal("refresh completed before PostgreSQL observed the account lock wait")
		case <-ctx.Done():
			t.Fatal("PostgreSQL did not observe the account lock wait")
		case <-ticker.C:
		}
	}
	if commitErr := blocker.Commit(ctx); commitErr != nil {
		t.Fatal(commitErr)
	}
	if err := <-finished; !errors.Is(err, sessioncase.ErrUnauthenticated) {
		t.Fatalf("disabled account after lock wait: %v", err)
	}
	var generation int64
	if readErr := f.pool.QueryRow(
		ctx,
		`SELECT max(generation) FROM identity.refresh_credentials WHERE session_id=$1`,
		f.current.ID,
	).Scan(&generation); readErr != nil ||
		generation != 0 {
		t.Fatal("disabled account rotated a credential")
	}
}
