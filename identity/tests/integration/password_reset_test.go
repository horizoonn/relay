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

	"github.com/horizoonn/relay/identity/internal/domain"
	"github.com/horizoonn/relay/identity/internal/mailcipher"
	"github.com/horizoonn/relay/identity/internal/password"
	tokenrepo "github.com/horizoonn/relay/identity/internal/repository/postgres/accounttoken"
	emailrepo "github.com/horizoonn/relay/identity/internal/repository/postgres/emailjob"
	sessionrepo "github.com/horizoonn/relay/identity/internal/repository/postgres/session"
	userrepo "github.com/horizoonn/relay/identity/internal/repository/postgres/user"
	"github.com/horizoonn/relay/identity/internal/secret"
	"github.com/horizoonn/relay/identity/internal/usecase/account"
	"github.com/horizoonn/relay/identity/internal/usecase/email"
)

// SQL tests use a precomputed real hash so Argon2 capacity cannot prevent two
// operations from reaching the database. Component tests retain the real hasher.
type fixedResetPasswordHash string

func (h fixedResetPasswordHash) Hash(ctx context.Context, _ string) (string, error) {
	return string(h), ctx.Err()
}

const replacementPassword = "replacement sufficiently long password"

type resetFixture struct {
	lifecycleFixture
	tx               *postgres.TxManager
	users            *userrepo.Repository
	tokens           *tokenrepo.Repository
	user             domain.User
	raw              string
	hashes           [][32]byte
	activeSessions   []domain.Session
	oldHash, newHash string
}

func newResetFixture(t *testing.T) (resetFixture, context.Context) {
	t.Helper()
	base, ctx := lifecycle(t)
	f := resetFixture{lifecycleFixture: base, tx: postgres.NewTxManager(base.pool)}
	f.users = userrepo.NewRepository(f.tx.Executor, 15*time.Second)
	f.tokens = tokenrepo.NewRepository(f.tx.Executor, 15*time.Second)
	f.sessions = sessionrepo.NewRepository(f.tx.Executor, 15*time.Second)
	if _, err := f.pool.Exec(ctx, `UPDATE identity.users SET email_verified_at=NULL WHERE id=$1`, f.current.UserID); err != nil {
		t.Fatal(err)
	}
	var err error
	f.user, err = f.users.Get(ctx, f.current.UserID)
	if err != nil {
		t.Fatal(err)
	}
	f.oldHash, err = f.users.GetPasswordHash(ctx, f.current.UserID)
	if err != nil {
		t.Fatal(err)
	}
	f.newHash, err = password.Hash(replacementPassword)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	f.activeSessions = []domain.Session{f.current, addSession(t, base, ctx, now, now.Add(time.Hour))}
	for range 2 {
		raw, err := secret.Generate()
		if err != nil {
			t.Fatal(err)
		}
		hash, err := secret.Digest(raw)
		if err != nil {
			t.Fatal(err)
		}
		token := domain.AccountToken{
			Hash: hash, UserID: f.user.ID, Purpose: domain.ResetPassword,
			CreatedAt: now, ExpiresAt: now.Add(domain.ResetPassword.Lifetime()),
		}
		if err := f.tokens.Create(ctx, token); err != nil {
			t.Fatal(err)
		}
		if f.raw == "" {
			f.raw = raw
		}
		f.hashes = append(f.hashes, hash)
	}
	return f, ctx
}

func (f resetFixture) accounts(t *testing.T, users account.UserRepository, tx account.Transactor, queue email.EmailQueue) *account.Service {
	t.Helper()
	cipher, err := mailcipher.New([]byte("reset-test-mail-encryption-key-at-least-32-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	requests, err := email.NewRequests(queue, cipher, unlimitedLimiter{})
	if err != nil {
		t.Fatal(err)
	}
	service, err := account.NewService(users, f.tokens, f.sessions, tx, fixedResetPasswordHash(f.newHash), requests)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestPasswordResetRollback(t *testing.T) {
	for _, tt := range []struct {
		name       string
		queueFails bool
	}{
		{"notification insert fails after writing", true},
		{"transaction rejects after callback", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f, ctx := newResetFixture(t)
			failure := errors.New("late reset failure")
			queue := &failedEmailQueue{Repository: emailrepo.NewRepository(f.tx.Executor, 15*time.Second)}
			cleanupResetNotification(t, f, queue)
			var tx account.Transactor = f.tx
			if tt.queueFails {
				queue.err = failure
			} else {
				tx = abortAfterCallback{TxManager: f.tx, err: failure}
			}
			service := f.accounts(t, f.users, tx, queue)
			if err := service.ResetPassword(ctx, f.raw, replacementPassword); !errors.Is(err, failure) {
				t.Fatalf("reset error=%v; want late failure", err)
			}
			user, hash, err := f.users.GetByEmailWithPasswordHash(ctx, f.user.Email)
			if err != nil {
				t.Fatal(err)
			}
			if hash != f.oldHash {
				t.Fatal("rolled-back reset changed password")
			}
			if user.EmailVerifiedAt != nil {
				t.Fatal("rolled-back reset verified email")
			}
			if !user.UpdatedAt.Equal(f.user.UpdatedAt) {
				t.Fatal("rolled-back reset changed user timestamp")
			}
			for _, session := range f.activeSessions {
				stored, err := f.sessions.Get(ctx, f.user.ID, session.ID)
				if err != nil {
					t.Fatal(err)
				}
				if stored.RevokedAt != nil {
					t.Fatalf("rolled-back reset revoked session %s", session.ID)
				}
			}
			for _, hash := range f.hashes {
				token, err := f.tokens.Get(ctx, hash)
				if err != nil {
					t.Fatal(err)
				}
				if token.UsedAt != nil {
					t.Fatal("rolled-back reset consumed an account token")
				}
			}
			var jobs int
			if queue.id == uuid.Nil() {
				t.Fatal("failure did not reach notification insertion")
			}
			if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM identity.email_jobs WHERE id=$1`, queue.id).Scan(&jobs); err != nil {
				t.Fatal(err)
			}
			if jobs != 0 {
				t.Fatal("rolled-back reset persisted notification")
			}
			queue.err = nil
			retry := f.accounts(t, f.users, f.tx, queue)
			if err := retry.ResetPassword(ctx, f.raw, replacementPassword); err != nil {
				t.Fatalf("token is not reusable after rollback: %v", err)
			}
		})
	}
}

func TestConcurrentPasswordReset(t *testing.T) {
	f, ctx := newResetFixture(t)
	reached, release := make(chan struct{}), make(chan struct{})
	heldPID, waitingPID := make(chan uint32, 1), make(chan uint32, 1)
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	held := heldTransaction{TxManager: f.tx, reached: reached, backendPID: heldPID, release: release}
	queue := emailrepo.NewRepository(f.tx.Executor, 15*time.Second)
	firstQueue := &failedEmailQueue{Repository: queue}
	cleanupResetNotification(t, f, firstQueue)
	first := f.accounts(t, f.users, held, firstQueue)
	observer := observingUserRepository{Repository: f.users, executor: f.tx.Executor, backendPID: waitingPID}
	second := f.accounts(t, observer, f.tx, queue)
	firstDone, secondDone := make(chan error, 1), make(chan error, 1)
	go func() { firstDone <- first.ResetPassword(ctx, f.raw, replacementPassword) }()
	select {
	case <-reached:
	case err := <-firstDone:
		t.Fatalf("first reset failed before commit barrier: %v", err)
	case <-ctx.Done():
		t.Fatal("first reset did not reach commit barrier")
	}
	go func() { secondDone <- second.ResetPassword(ctx, f.raw, replacementPassword) }()
	var pid uint32
	select {
	case pid = <-waitingPID:
	case <-ctx.Done():
		t.Fatal("second reset did not attempt account lock")
	}
	waitForAccountLock(t, ctx, f.pool, pid, <-heldPID)
	unblock()
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if err := <-secondDone; !errors.Is(err, account.ErrInvalidToken) {
		t.Fatalf("second reset error=%v; want ErrInvalidToken", err)
	}
	_, hash, err := f.users.GetByEmailWithPasswordHash(ctx, f.user.Email)
	if err != nil {
		t.Fatal(err)
	}
	if hash != f.newHash {
		t.Fatal("successful reset did not save replacement password")
	}
	for _, hash := range f.hashes {
		token, err := f.tokens.Get(ctx, hash)
		if err != nil {
			t.Fatal(err)
		}
		if token.UsedAt == nil {
			t.Fatal("successful reset left a reset token active")
		}
	}
	for _, session := range f.activeSessions {
		stored, err := f.sessions.Get(ctx, f.user.ID, session.ID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.RevokedAt == nil {
			t.Fatal("successful reset left a session active")
		}
	}
}

func cleanupResetNotification(t *testing.T, f resetFixture, queue *failedEmailQueue) {
	t.Helper()
	t.Cleanup(func() {
		if queue.id == uuid.Nil() {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := f.pool.Exec(ctx, `DELETE FROM identity.email_jobs WHERE id=$1`, queue.id); err != nil {
			t.Errorf("clean up reset notification: %v", err)
		}
	})
}
