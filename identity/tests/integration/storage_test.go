//go:build integration

package integration

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/platform/pkg/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/horizoonn/relay/identity/internal/domain"
	identitylimit "github.com/horizoonn/relay/identity/internal/ratelimit"
	sessionrepo "github.com/horizoonn/relay/identity/internal/repository/postgres/session"
	userrepo "github.com/horizoonn/relay/identity/internal/repository/postgres/user"
	"github.com/horizoonn/relay/identity/internal/secret"
)

func testPool(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("RELAY_IDENTITY_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("RELAY_IDENTITY_TEST_DATABASE_URL must point to an isolated migrated Identity database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close(); cancel() })
	if err := pool.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	return pool, ctx
}

func cleanupUser(t *testing.T, pool *pgxpool.Pool, id uuid.UUID) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := pool.Exec(ctx, `DELETE FROM identity.users WHERE id = $1`, id); err != nil {
			t.Error(err)
		}
	})
}

func digest(t *testing.T) [32]byte {
	t.Helper()
	raw, err := secret.Generate()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := secret.Digest(raw)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func TestConcurrentRegistration(t *testing.T) {
	pool, ctx := testPool(t)
	tx := postgres.NewTxManager(pool)
	users := userrepo.NewRepository(tx.Executor, 15*time.Second)
	email := uuid.NewV7().String() + "@example.com"
	first, err := domain.NewUser(email, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	second, err := domain.NewUser(email, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	cleanupUser(t, pool, first.ID)
	cleanupUser(t, pool, second.ID)
	reached, release := make(chan struct{}), make(chan struct{})
	heldPID, waitingPID := make(chan uint32, 1), make(chan uint32, 1)
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	held := heldTransaction{TxManager: tx, reached: reached, backendPID: heldPID, release: release}
	firstDone, secondDone := make(chan error, 1), make(chan error, 1)
	go func() {
		firstDone <- held.WithinTransaction(ctx, func(ctx context.Context) error { return users.Create(ctx, first, "test-phc") })
	}()
	select {
	case <-reached:
	case firstErr := <-firstDone:
		t.Fatalf("first registration failed before commit barrier: %v", firstErr)
	case <-ctx.Done():
		t.Fatal("first registration did not reach commit barrier")
	}
	go func() {
		secondDone <- tx.WithinTransaction(ctx, func(ctx context.Context) error {
			waitingPID <- tx.Executor(ctx).(pgx.Tx).Conn().PgConn().PID()
			return users.Create(ctx, second, "test-phc")
		})
	}()
	var pid uint32
	select {
	case pid = <-waitingPID:
	case <-ctx.Done():
		t.Fatal("second registration did not reach PostgreSQL")
	}
	waitForAccountLock(t, ctx, pool, pid, <-heldPID)
	unblock()
	if firstErr := <-firstDone; firstErr != nil {
		t.Fatal(firstErr)
	}
	if secondErr := <-secondDone; !errors.Is(secondErr, domain.ErrEmailAlreadyRegistered) {
		t.Fatalf("duplicate email error=%v", secondErr)
	}
	user, hash, err := users.GetByEmailWithPasswordHash(ctx, email)
	if err != nil {
		t.Fatal(err)
	}
	if user.ID != first.ID || hash != "test-phc" {
		t.Fatal("duplicate registration replaced the committed account")
	}
	if _, err := users.Get(ctx, second.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("losing registration left an account: %v", err)
	}
}

func TestCreateSessionStoresRefreshCredential(t *testing.T) {
	pool, ctx := testPool(t)
	tx := postgres.NewTxManager(pool)
	users := userrepo.NewRepository(tx.Executor, 5*time.Second)
	sessions := sessionrepo.NewRepository(tx.Executor, 5*time.Second)
	now := time.Now().UTC().Truncate(time.Microsecond)
	user, err := domain.NewUser(uuid.NewV7().String()+"@example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	cleanupUser(t, pool, user.ID)
	if err = users.Create(ctx, user, "test-phc"); err != nil {
		t.Fatal(err)
	}
	session, err := domain.NewSession(user.ID, digest(t), now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	refresh := digest(t)
	if err = sessions.Create(ctx, session, refresh); err != nil {
		t.Fatal(err)
	}
	stored, err := sessions.Get(ctx, user.ID, session.ID)
	if err != nil || !stored.Active(now) || stored.CSRFHash != session.CSRFHash {
		t.Fatalf("session roundtrip: %v", err)
	}
	if _, err = sessions.Get(ctx, uuid.NewV7(), session.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("foreign session returned")
	}
	if err = sessions.Revoke(ctx, uuid.NewV7(), session.ID, now); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("foreign session revoked")
	}
	if err = sessions.Revoke(ctx, user.ID, session.ID, now); err != nil {
		t.Fatal(err)
	}
	if err = sessions.Revoke(ctx, user.ID, session.ID, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	stored, err = sessions.Get(ctx, user.ID, session.ID)
	if err != nil || stored.Active(now) || stored.RevokedAt == nil || !stored.RevokedAt.Equal(now) {
		t.Fatal("revocation is not idempotent")
	}

	second, err := domain.NewSession(user.ID, digest(t), now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := sessions.Create(ctx, second, refresh); err == nil {
		t.Fatal("duplicate refresh accepted")
	}
	if _, err := sessions.Get(ctx, user.ID, second.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("failed refresh insertion left a session")
	}
}

func TestRegistrationTransactionRollback(t *testing.T) {
	pool, ctx := testPool(t)
	tx := postgres.NewTxManager(pool)
	users := userrepo.NewRepository(tx.Executor, 5*time.Second)
	user, err := domain.NewUser(uuid.NewV7().String()+"@example.com", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	cleanupUser(t, pool, user.ID)
	abort := errors.New("abort registration")
	err = tx.WithinTransaction(ctx, func(ctx context.Context) error {
		if createErr := users.Create(ctx, user, "test-phc"); createErr != nil {
			return createErr
		}
		return abort
	})
	if !errors.Is(err, abort) {
		t.Fatal(err)
	}
	if _, _, err = users.GetByEmailWithPasswordHash(ctx, user.Email); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("rolled-back user was persisted")
	}
}

func TestStorageConstraints(t *testing.T) {
	pool, ctx := testPool(t)
	tx := postgres.NewTxManager(pool)
	users := userrepo.NewRepository(tx.Executor, 5*time.Second)
	user, err := domain.NewUser(uuid.NewV7().String()+"@example.com", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	cleanupUser(t, pool, user.ID)
	if err := users.Create(ctx, user, "test-phc"); err != nil {
		t.Fatal(err)
	}
	const insertSession = `
		INSERT INTO identity.sessions
			(id, user_id, csrf_hash, created_at, authenticated_at, last_seen_at, expires_at)
		VALUES ($1, $2, $3, now(), now(), now(), now() + interval '45 days')
	`
	if _, err := pool.Exec(ctx, insertSession, uuid.NewV7(), user.ID, []byte{1}); err == nil {
		t.Fatal("short hash accepted")
	}
	if _, err := pool.Exec(ctx, insertSession, uuid.NewV7(), uuid.NewV7(), make([]byte, 32)); err == nil {
		t.Fatal("orphan session accepted")
	}
	sessionID := uuid.NewV7()
	if _, err := pool.Exec(ctx, insertSession, sessionID, user.ID, make([]byte, 32)); err != nil {
		t.Fatalf("database imposed business TTL: %v", err)
	}
	const insertRefresh = `
		INSERT INTO identity.refresh_credentials
			(token_hash, session_id, generation, created_at, expires_at)
		VALUES ($1, $2, $3, now(), now() + interval '45 days')
	`
	first, second := digest(t), digest(t)
	if _, err := pool.Exec(ctx, insertRefresh, first[:], sessionID, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, insertRefresh, second[:], sessionID, 1); err == nil {
		t.Fatal("multiple current refresh credentials accepted")
	}
	if _, err := pool.Exec(
		ctx,
		`UPDATE identity.refresh_credentials SET used_at = now() WHERE token_hash = $1`,
		first[:],
	); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, insertRefresh, second[:], sessionID, 1); err != nil {
		t.Fatal(err)
	}
}

type unlimitedLimiter struct{}

func (unlimitedLimiter) Allow(context.Context, identitylimit.Scope, string) error { return nil }

type discardVerification struct{}

func (discardVerification) QueueVerification(context.Context, string) error { return nil }
func verifyTestUser(t *testing.T, pool *pgxpool.Pool, id uuid.UUID) {
	t.Helper()
	tx := postgres.NewTxManager(pool)
	users := userrepo.NewRepository(tx.Executor, 5*time.Second)
	if err := users.VerifyEmail(t.Context(), id, time.Now()); err != nil {
		t.Fatal(err)
	}
}
