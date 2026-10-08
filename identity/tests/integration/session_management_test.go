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
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/horizoonn/relay/identity/internal/domain"
	"github.com/horizoonn/relay/identity/internal/password"
	sessionrepo "github.com/horizoonn/relay/identity/internal/repository/postgres/session"
	userrepo "github.com/horizoonn/relay/identity/internal/repository/postgres/user"
	"github.com/horizoonn/relay/identity/internal/usecase/auth"
	sessioncase "github.com/horizoonn/relay/identity/internal/usecase/session"
)

func addSession(
	t *testing.T,
	f lifecycleFixture,
	ctx context.Context,
	created, expires time.Time,
) domain.Session {
	t.Helper()
	value, err := domain.NewSession(f.current.UserID, digest(t), created, expires)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.sessions.Create(ctx, value, digest(t)); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestListSessionsPagination(t *testing.T) {
	f, ctx := lifecycle(t)
	foreign, _ := lifecycle(t)
	now := time.Now().UTC().Truncate(time.Microsecond)

	created := now.Add(-10 * time.Second)
	first := addSession(t, f, ctx, created, now.Add(time.Hour))
	second := addSession(t, f, ctx, created, now.Add(time.Hour))
	revoked := addSession(t, f, ctx, now.Add(-2*time.Second), now.Add(time.Hour))
	if err := f.sessions.Revoke(ctx, f.current.UserID, revoked.ID, now); err != nil {
		t.Fatal(err)
	}
	addSession(t, f, ctx, now.Add(-2*time.Hour), now)
	addSession(t, f, ctx, now.Add(time.Minute), now.Add(time.Hour))
	if first.ID.String() < second.ID.String() {
		first, second = second, first
	}
	expected := []uuid.UUID{first.ID, second.ID, f.current.ID}
	var after *sessioncase.Anchor
	for i, want := range expected {
		page, err := f.sessions.ListActive(ctx, f.current.UserID, now, sessioncase.ListParams{
			Limit: 1,
			After: after,
		})
		if err != nil || len(page.Sessions) != 1 || page.Sessions[0].ID != want {
			t.Fatalf("page %d: %+v error=%v", i, page, err)
		}
		if page.Sessions[0].ID == foreign.current.ID {
			t.Fatal("foreign session exposed")
		}
		if i < len(expected)-1 {
			if page.Next == nil || !page.Next.CreatedAt.Equal(created) {
				t.Fatal("cursor lost timestamp precision")
			}
		} else if page.Next != nil {
			t.Fatal("terminal page has a cursor")
		}
		after = page.Next
	}
	current, err := f.sessions.Get(ctx, f.current.UserID, f.current.ID)
	if err != nil || !current.LastSeenAt.Equal(f.current.LastSeenAt) {
		t.Fatal("listing changed activity")
	}
}

func TestRevokeSessionsOwnerScope(t *testing.T) {
	for _, tc := range []struct {
		name string
		all  bool
	}{{
		name: "selected",
		all:  false,
	}, {
		name: "all",
		all:  true,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			f, ctx := lifecycle(t)
			foreign, _ := lifecycle(t)
			target := addSession(t, f, ctx, f.current.CreatedAt, f.current.ExpiresAt)
			if err := f.service.Revoke(
				ctx,
				f.current.UserID,
				f.current.ID,
				foreign.current.ID,
				f.rawCSRF,
			); !errors.Is(err, sessioncase.ErrSessionNotFound) {
				t.Fatalf("foreign target: %v", err)
			}
			if err := f.service.Revoke(
				ctx,
				f.current.UserID,
				f.current.ID,
				uuid.NewV7(),
				f.rawCSRF,
			); !errors.Is(err, sessioncase.ErrSessionNotFound) {
				t.Fatalf("missing target: %v", err)
			}
			rotated, err := f.service.Refresh(ctx, f.rawRefresh, f.rawCSRF)
			if err != nil {
				t.Fatal(err)
			}
			if tc.all {
				err = f.service.RevokeAll(ctx, f.current.UserID, f.current.ID, f.rawCSRF)
			} else {
				err = f.service.Revoke(ctx, f.current.UserID, f.current.ID, target.ID, f.rawCSRF)
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, expected := range []struct {
				session domain.Session
				revoked bool
			}{
				{
					session: target,
					revoked: true,
				}, {
					session: f.current,
					revoked: tc.all,
				}, {
					session: foreign.current,
					revoked: false,
				},
			} {
				stored, err := f.sessions.Get(ctx, expected.session.UserID, expected.session.ID)
				if err != nil || (stored.RevokedAt != nil) != expected.revoked {
					t.Fatalf("incorrect revocation: %v", err)
				}
			}
			var history int
			if err := f.pool.QueryRow(
				ctx,
				`SELECT count(*) FROM identity.refresh_credentials WHERE session_id=$1`,
				f.current.ID,
			).Scan(&history); err != nil ||
				history != 2 {
				t.Fatalf("revocation discarded history: %d %v", history, err)
			}
			if tc.all {
				if _, err := f.service.Refresh(ctx, rotated.RefreshToken, f.rawCSRF); !errors.Is(
					err, sessioncase.ErrUnauthenticated,
				) {
					t.Fatalf("refresh survived revoke all: %v", err)
				}
				if _, err := f.service.ListActive(ctx, f.current.UserID, f.current.ID, sessioncase.ListParams{
					Limit: 20,
				}); !errors.Is(err, sessioncase.ErrUnauthenticated) {
					t.Fatalf("revoked caller listed sessions: %v", err)
				}
				if err := f.service.RevokeAll(
					ctx,
					f.current.UserID,
					f.current.ID,
					f.rawCSRF,
				); !errors.Is(err, sessioncase.ErrUnauthenticated) {
					t.Fatalf("revoked caller managed sessions: %v", err)
				}
			} else {
				stored, err := f.sessions.Get(ctx, f.current.UserID, target.ID)
				if err != nil {
					t.Fatal(err)
				}
				if err = f.service.Revoke(ctx, f.current.UserID, f.current.ID, target.ID, f.rawCSRF); err != nil {
					t.Fatal(err)
				}
				again, err := f.sessions.Get(ctx, f.current.UserID, target.ID)
				if err != nil || !again.RevokedAt.Equal(*stored.RevokedAt) {
					t.Fatal("repeat changed revocation time")
				}
			}
		})
	}
}

func TestSessionManagementRollback(t *testing.T) {
	for _, tc := range []struct {
		name string
		all  bool
	}{{
		name: "selected",
		all:  false,
	}, {
		name: "all",
		all:  true,
	}} {
		t.Run(tc.name, func(t *testing.T) {
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
			if tc.all {
				err = service.RevokeAll(ctx, f.current.UserID, f.current.ID, f.rawCSRF)
			} else {
				err = service.Revoke(ctx, f.current.UserID, f.current.ID, f.current.ID, f.rawCSRF)
			}
			if !errors.Is(err, rejected) {
				t.Fatal(err)
			}
			stored, err := f.sessions.Get(ctx, f.current.UserID, f.current.ID)
			if err != nil || stored.RevokedAt != nil {
				t.Fatal("aborted management committed revocation")
			}
		})
	}
}

func TestRevokeAndRefreshRaceCannotRestoreSession(t *testing.T) {
	for _, tt := range []struct {
		name              string
		all, refreshFirst bool
	}{
		{"refresh before current revocation", false, true},
		{"current revocation before refresh", false, false},
		{"refresh before revoke all", true, true},
		{"revoke all before refresh", true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f, ctx := lifecycle(t)
			race := newSessionLockRace(t, f)
			refreshed, revoked := make(chan error, 1), make(chan error, 1)
			refresh := func(service *sessioncase.Service) {
				_, err := service.Refresh(ctx, f.rawRefresh, f.rawCSRF)
				refreshed <- err
			}
			revoke := func(service *sessioncase.Service) {
				if tt.all {
					revoked <- service.RevokeAll(ctx, f.current.UserID, f.current.ID, f.rawCSRF)
				} else {
					revoked <- service.Revoke(ctx, f.current.UserID, f.current.ID, f.current.ID, f.rawCSRF)
				}
			}
			if tt.refreshFirst {
				go refresh(race.first)
				race.awaitFirst(t, ctx, refreshed)
				go revoke(race.second)
			} else {
				go revoke(race.first)
				race.awaitFirst(t, ctx, revoked)
				go refresh(race.second)
			}
			race.releaseAfterLockWait(t, ctx)
			if err := <-revoked; err != nil {
				t.Fatal(err)
			}
			refreshErr := <-refreshed
			if tt.refreshFirst {
				if refreshErr != nil {
					t.Fatal(refreshErr)
				}
			} else if !errors.Is(refreshErr, sessioncase.ErrUnauthenticated) {
				t.Fatalf("refresh after revocation: %v", refreshErr)
			}
			stored, err := f.sessions.Get(ctx, f.current.UserID, f.current.ID)
			if err != nil {
				t.Fatal(err)
			}
			if stored.RevokedAt == nil {
				t.Fatal("refresh restored a revoked session")
			}
			if _, err := f.service.Refresh(ctx, f.rawRefresh, f.rawCSRF); !errors.Is(err, sessioncase.ErrUnauthenticated) {
				t.Fatalf("revoked refresh accepted: %v", err)
			}
		})
	}
}

func waitForAccountLock(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	blocked, blocker uint32,
) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	const query = `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
        WHERE pid=$1 AND wait_event_type='Lock' AND $2=ANY(pg_blocking_pids(pid)))`
	for {
		var waiting bool
		if err := pool.QueryRow(ctx, query, blocked, blocker).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("account lock wait was not observed")
		case <-ticker.C:
		}
	}
}

func TestManagementCallerRace(t *testing.T) {
	f, ctx := lifecycle(t)
	tx := postgres.NewTxManager(f.pool)
	pids := make(chan uint32, 1)
	users := observingUserRepository{
		Repository: userrepo.NewRepository(tx.Executor, 5*time.Second),
		executor:   tx.Executor,
		backendPID: pids,
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
	if _, err := blocker.Exec(ctx, `SELECT id FROM identity.users WHERE id=$1 FOR UPDATE`, f.current.UserID); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- service.RevokeAll(ctx, f.current.UserID, f.current.ID, f.rawCSRF) }()
	var pid uint32
	select {
	case pid = <-pids:
	case <-ctx.Done():
		t.Fatal("management did not attempt the account lock")
	}
	waitForAccountLock(t, ctx, f.pool, pid, blocker.Conn().PgConn().PID())
	if _, err := blocker.Exec(ctx, `UPDATE identity.sessions SET revoked_at=now() WHERE id=$1`, f.current.ID); err != nil {
		t.Fatal(err)
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, sessioncase.ErrUnauthenticated) {
		t.Fatalf("revoked caller after lock wait: %v", err)
	}
}

type heldTransaction struct {
	*postgres.TxManager
	reached    chan struct{}
	backendPID chan uint32
	release    <-chan struct{}
}

func (tx heldTransaction) WithinTransaction(ctx context.Context, fn func(context.Context) error) error {
	return tx.TxManager.WithinTransaction(ctx, func(ctx context.Context) error {
		if err := fn(ctx); err != nil {
			return err
		}
		tx.backendPID <- tx.Executor(ctx).(pgx.Tx).Conn().PgConn().PID()
		close(tx.reached)
		select {
		case <-tx.release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
}

func TestRevokeAllSerializesWithLogin(t *testing.T) {
	for _, tc := range []struct {
		name       string
		loginFirst bool
	}{
		{
			name:       "login committed before revoke all is revoked",
			loginFirst: true,
		},
		{
			name:       "login committed after revoke all remains active",
			loginFirst: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, ctx := lifecycle(t)
			const value = "session management concurrency password"
			hash, err := password.Hash(value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.pool.Exec(
				ctx,
				`UPDATE identity.password_credentials SET password_hash=$2 WHERE user_id=$1`,
				f.current.UserID,
				hash,
			); err != nil {
				t.Fatal(err)
			}
			tx := postgres.NewTxManager(f.pool)
			users := userrepo.NewRepository(tx.Executor, 5*time.Second)
			user, err := users.Get(ctx, f.current.UserID)
			if err != nil {
				t.Fatal(err)
			}
			sessions := sessionrepo.NewRepository(tx.Executor, 5*time.Second)
			pids := make(chan uint32, 1)
			observer := observingUserRepository{
				Repository: users,
				executor:   tx.Executor,
				backendPID: pids,
			}
			reached, release := make(chan struct{}), make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			defer unblock()
			heldPIDs := make(chan uint32, 1)
			held := heldTransaction{
				TxManager:  tx,
				reached:    reached,
				backendPID: heldPIDs,
				release:    release,
			}
			var loginUsers auth.UserRepository = users
			var managementUsers sessioncase.UserRepository = users
			var loginTx auth.Transactor = tx
			var managementTx sessioncase.Transactor = tx
			if tc.loginFirst {
				loginTx = held
				managementUsers = observer
			} else {
				managementTx = held
				loginUsers = observer
			}
			login, err := auth.NewService(
				t.Context(),
				loginUsers,
				sessions,
				loginTx,
				f.issuer,
				testPasswordHasher(t),
				unlimitedLimiter{},
				discardVerification{},
			)
			if err != nil {
				t.Fatal(err)
			}
			management, err := sessioncase.NewService(managementUsers, sessions, managementTx, f.issuer)
			if err != nil {
				t.Fatal(err)
			}
			type loginResult struct {
				value auth.LoginResult
				err   error
			}
			loggedIn := make(chan loginResult, 1)
			revoked := make(chan error, 1)
			doLogin := func() {
				result, loginErr := login.Login(ctx, user.Email, value)
				loggedIn <- loginResult{
					result,
					loginErr,
				}
			}
			doRevoke := func() { revoked <- management.RevokeAll(ctx, user.ID, f.current.ID, f.rawCSRF) }
			if tc.loginFirst {
				go doLogin()
			} else {
				go doRevoke()
			}
			select {
			case <-reached:
			case <-ctx.Done():
				t.Fatal("first transaction did not reach the commit barrier")
			}
			if tc.loginFirst {
				go doRevoke()
			} else {
				go doLogin()
			}
			var pid uint32
			select {
			case pid = <-pids:
			case <-ctx.Done():
				t.Fatal("second transaction did not attempt the account lock")
			}
			blocker := <-heldPIDs
			waitForAccountLock(t, ctx, f.pool, pid, blocker)
			unblock()
			result := <-loggedIn
			if result.err != nil {
				t.Fatal(result.err)
			}
			if revokeErr := <-revoked; revokeErr != nil {
				t.Fatal(revokeErr)
			}
			stored, err := sessions.Get(ctx, user.ID, result.value.SessionID)
			if err != nil || (stored.RevokedAt != nil) != tc.loginFirst {
				t.Fatalf("incorrect login/revoke ordering: %v", err)
			}
			_, err = f.service.Refresh(ctx, result.value.RefreshToken, result.value.CSRFToken)
			if tc.loginFirst && !errors.Is(err, sessioncase.ErrUnauthenticated) {
				t.Fatalf("login before revoke retained refresh: %v", err)
			}
			if !tc.loginFirst && err != nil {
				t.Fatalf("login after revoke lost refresh: %v", err)
			}
		})
	}
}
