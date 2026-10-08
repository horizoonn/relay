//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/platform/pkg/postgres"
	"github.com/horizoonn/relay/platform/pkg/security/accessjwt"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/argon2"

	"github.com/horizoonn/relay/identity/internal/domain"
	"github.com/horizoonn/relay/identity/internal/password"
	sessionrepo "github.com/horizoonn/relay/identity/internal/repository/postgres/session"
	userrepo "github.com/horizoonn/relay/identity/internal/repository/postgres/user"
	"github.com/horizoonn/relay/identity/internal/secret"
	"github.com/horizoonn/relay/identity/internal/usecase/auth"
)

func authService(t *testing.T, pool *pgxpool.Pool) (*auth.Service, *accessjwt.Verifier) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := accessjwt.NewIssuer("test", private)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := accessjwt.NewVerifier(map[string]ed25519.PublicKey{"test": public})
	if err != nil {
		t.Fatal(err)
	}
	tx := postgres.NewTxManager(pool)
	service, err := auth.NewService(
		t.Context(),
		userrepo.NewRepository(tx.Executor, 5*time.Second),
		sessionrepo.NewRepository(tx.Executor, 5*time.Second),
		tx,
		issuer,
		testPasswordHasher(t),
		unlimitedLimiter{},
		discardVerification{},
	)
	if err != nil {
		t.Fatal(err)
	}
	return service, verifier
}

func TestRegisterAndPasswordLogin(t *testing.T) {
	pool, ctx := testPool(t)
	service, verifier := authService(t, pool)
	email := uuid.NewV7().String() + "@EXAMPLE.COM"
	const value = "пароль с пробелами и Unicode 🔐"
	id, err := service.Register(ctx, email, value)
	if err != nil {
		t.Fatal(err)
	}
	cleanupUser(t, pool, id)
	verifyTestUser(t, pool, id)
	if _, err = service.Register(ctx, email, value); !errors.Is(err, domain.ErrEmailAlreadyRegistered) {
		t.Fatalf("duplicate: %v", err)
	}
	result, err := service.Login(ctx, email, value)
	if err != nil {
		t.Fatal(err)
	}
	access, err := verifier.Verify(result.AccessToken)
	if err != nil || access.UserID != id || access.SessionID != result.SessionID {
		t.Fatalf("access claims: %v", err)
	}
	csrfHash, err := secret.Digest(result.CSRFToken)
	if err != nil || access.CSRFHash != csrfHash {
		t.Fatal("CSRF is not bound to access")
	}
	refreshHash, err := secret.Digest(result.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	var storedUser uuid.UUID
	var storedCSRF []byte
	var created, expiry time.Time
	err = pool.QueryRow(ctx, `
		SELECT s.user_id, s.csrf_hash, s.created_at, s.expires_at
		FROM identity.refresh_credentials r JOIN identity.sessions s ON s.id = r.session_id
		WHERE r.token_hash = $1 AND r.used_at IS NULL`, refreshHash[:]).Scan(&storedUser, &storedCSRF, &created, &expiry)
	if err != nil || storedUser != id || !bytes.Equal(storedCSRF, csrfHash[:]) || !expiry.Equal(result.SessionExpiresAt) {
		t.Fatalf("stored credentials: %v", err)
	}
	if !expiry.Equal(created.Add(domain.MaxSessionLifetime)) || access.ExpiresAt.After(expiry) {
		t.Fatal("issued credentials exceed session lifetime policy")
	}
	for _, attempt := range []struct {
		email    string
		password string
	}{
		{
			email:    email,
			password: "wrong password",
		}, {
			email:    uuid.NewV7().String() + "@example.com",
			password: value,
		},
	} {
		if _, err := service.Login(ctx, attempt.email, attempt.password); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("invalid login: %v", err)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE identity.users SET state = 'disabled' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Login(ctx, email, value); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("disabled login: %v", err)
	}
	var count int
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*) FROM identity.sessions WHERE user_id = $1`,
		id,
	).Scan(&count); err != nil ||
		count != 1 {
		t.Fatalf("session count=%d err=%v", count, err)
	}
}

func TestRegisterRejectsInvalidInputBeforeStorage(t *testing.T) {
	pool, ctx := testPool(t)
	service, _ := authService(t, pool)
	email := uuid.NewV7().String() + "@example.com"
	for _, attempt := range []struct {
		email    string
		password string
		want     error
	}{
		{
			email:    "invalid-email",
			password: "a sufficiently long password",
			want:     domain.ErrInvalidEmail,
		},
		{
			email:    email,
			password: "short password",
			want:     password.ErrInvalidPassword,
		},
		{
			email:    email,
			password: "a sufficiently long password\xff",
			want:     password.ErrInvalidPassword,
		},
	} {
		id, err := service.Register(ctx, attempt.email, attempt.password)
		if !errors.Is(err, attempt.want) || id != uuid.Nil() {
			t.Fatalf("invalid registration: id=%s error=%v", id, err)
		}
	}
	var count int
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*) FROM identity.users WHERE email = $1`,
		email,
	).Scan(&count); err != nil ||
		count != 0 {
		t.Fatalf("invalid input reached storage: count=%d error=%v", count, err)
	}
}

type failedIssuer struct {
	err error
}

func (i failedIssuer) Issue(uuid.UUID, uuid.UUID, [32]byte, time.Time) (accessjwt.Token, error) {
	return accessjwt.Token{}, i.err
}

func TestSigningFailureDoesNotCreateSession(t *testing.T) {
	pool, ctx := testPool(t)
	tx := postgres.NewTxManager(pool)
	failure := errors.New("signing failed")
	service, err := auth.NewService(t.Context(), userrepo.NewRepository(tx.Executor, time.Second),
		sessionrepo.NewRepository(tx.Executor, time.Second), tx, failedIssuer{
			failure,
		}, testPasswordHasher(t), unlimitedLimiter{}, discardVerification{})
	if err != nil {
		t.Fatal(err)
	}
	email := uuid.NewV7().String() + "@example.com"
	id, err := service.Register(ctx, email, "a sufficiently long password")
	if err != nil {
		t.Fatal(err)
	}
	cleanupUser(t, pool, id)
	verifyTestUser(t, pool, id)
	result, err := service.Login(ctx, email, "a sufficiently long password")
	if !errors.Is(err, failure) || result.AccessToken != "" || result.RefreshToken != "" {
		t.Fatal("failed login returned credentials")
	}
	var count int
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*) FROM identity.sessions WHERE user_id = $1`,
		id,
	).Scan(&count); err != nil ||
		count != 0 {
		t.Fatalf("orphan sessions=%d err=%v", count, err)
	}
}

type pausedUsers struct {
	*userrepo.Repository
	entered chan struct{}
	resume  chan struct{}
}

func (r *pausedUsers) GetForUpdate(ctx context.Context, id uuid.UUID) (domain.User, error) {
	close(r.entered)
	select {
	case <-r.resume:
		return r.Repository.GetForUpdate(ctx, id)
	case <-ctx.Done():
		return domain.User{}, ctx.Err()
	}
}

func TestLoginRechecksAccountAndCredential(t *testing.T) {
	for _, action := range []string{"disable", "change-password"} {
		t.Run(action, func(t *testing.T) {
			pool, ctx := testPool(t)
			tx := postgres.NewTxManager(pool)
			users := &pausedUsers{
				userrepo.NewRepository(tx.Executor, 5*time.Second),
				make(chan struct{}),
				make(chan struct{}),
			}
			_, private, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			issuer, err := accessjwt.NewIssuer("test", private)
			if err != nil {
				t.Fatal(err)
			}
			service, err := auth.NewService(
				t.Context(),
				users,
				sessionrepo.NewRepository(tx.Executor, 5*time.Second),
				tx,
				issuer,
				testPasswordHasher(t),
				unlimitedLimiter{},
				discardVerification{},
			)
			if err != nil {
				t.Fatal(err)
			}
			email := uuid.NewV7().String() + "@example.com"
			id, err := service.Register(ctx, email, "a sufficiently long password")
			if err != nil {
				t.Fatal(err)
			}
			cleanupUser(t, pool, id)
			verifyTestUser(t, pool, id)
			finished := make(chan error, 1)
			go func() {
				_, loginErr := service.Login(ctx, email, "a sufficiently long password")
				finished <- loginErr
			}()
			select {
			case <-users.entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if action == "disable" {
				_, err = pool.Exec(ctx, `UPDATE identity.users SET state = 'disabled' WHERE id = $1`, id)
			} else {
				var hash string
				hash, err = password.Hash("another sufficiently long password")
				if err == nil {
					_, err = pool.Exec(ctx, `UPDATE identity.password_credentials SET password_hash = $2 WHERE user_id = $1`, id, hash)
				}
			}
			close(users.resume)
			if err != nil {
				t.Fatal(err)
			}
			if err := <-finished; !errors.Is(err, auth.ErrInvalidCredentials) {
				t.Fatalf("stale login accepted: %v", err)
			}
			var count int
			if err := pool.QueryRow(
				ctx,
				`SELECT count(*) FROM identity.sessions WHERE user_id = $1`,
				id,
			).Scan(&count); err != nil ||
				count != 0 {
				t.Fatalf("stale login sessions=%d err=%v", count, err)
			}
		})
	}
}

func TestLoginRehashesPasswordAtomically(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprintf("signing-failure=%t", fail), func(t *testing.T) {
			pool, ctx := testPool(t)
			service, _ := authService(t, pool)
			const value = "a sufficiently long password"
			email := uuid.NewV7().String() + "@example.com"
			id, err := service.Register(ctx, email, value)
			if err != nil {
				t.Fatal(err)
			}
			cleanupUser(t, pool, id)
			verifyTestUser(t, pool, id)
			salt := []byte("a test salt only!")
			key := argon2.IDKey([]byte(value), salt, 2, 19*1024, 1, 32)
			oldHash := fmt.Sprintf("$argon2id$v=19$m=19456,t=2,p=1$%s$%s",
				base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
			if _, err = pool.Exec(
				ctx,
				`UPDATE identity.password_credentials SET password_hash = $2 WHERE user_id = $1`,
				id,
				oldHash,
			); err != nil {
				t.Fatal(err)
			}
			var changedAt time.Time
			if scanErr := pool.QueryRow(
				ctx,
				`SELECT updated_at FROM identity.password_credentials WHERE user_id = $1`,
				id,
			).Scan(&changedAt); scanErr != nil {
				t.Fatal(scanErr)
			}
			failure := errors.New("signing unavailable")
			if fail {
				tx := postgres.NewTxManager(pool)
				service, err = auth.NewService(t.Context(), userrepo.NewRepository(tx.Executor, time.Second),
					sessionrepo.NewRepository(tx.Executor, time.Second), tx, failedIssuer{
						failure,
					}, testPasswordHasher(t), unlimitedLimiter{}, discardVerification{})
				if err != nil {
					t.Fatal(err)
				}
			}
			_, err = service.Login(ctx, email, value)
			if fail && !errors.Is(err, failure) || !fail && err != nil {
				t.Fatalf("login: %v", err)
			}
			var storedHash string
			var storedChangedAt time.Time
			if err := pool.QueryRow(
				ctx,
				`SELECT password_hash, updated_at FROM identity.password_credentials WHERE user_id = $1`,
				id,
			).Scan(&storedHash, &storedChangedAt); err != nil {
				t.Fatal(err)
			}
			if !storedChangedAt.Equal(changedAt) {
				t.Fatal("login rehash changed the password change time")
			}
			if fail {
				if storedHash != oldHash {
					t.Fatal("failed login committed password rehash")
				}
			} else {
				needed, err := password.NeedsRehash(storedHash)
				if err != nil || needed {
					t.Fatalf("password was not upgraded: %v", err)
				}
				matched, err := password.Verify(value, storedHash)
				if err != nil || !matched {
					t.Fatalf("new hash does not match password: %v", err)
				}
			}
		})
	}
}

type abortAfterCallback struct {
	*postgres.TxManager
	err error
}

func (tx abortAfterCallback) WithinTransaction(ctx context.Context, fn func(context.Context) error) error {
	return tx.TxManager.WithinTransaction(ctx, func(ctx context.Context) error {
		if err := fn(ctx); err != nil {
			return err
		}
		return tx.err
	})
}

func TestLoginTransactionFailure(t *testing.T) {
	pool, ctx := testPool(t)
	tx := postgres.NewTxManager(pool)
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := accessjwt.NewIssuer("test", private)
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("transaction aborted after callback")
	service, err := auth.NewService(t.Context(), userrepo.NewRepository(tx.Executor, time.Second),
		sessionrepo.NewRepository(tx.Executor, time.Second), abortAfterCallback{
			tx,
			failure,
		}, issuer, testPasswordHasher(t), unlimitedLimiter{}, discardVerification{})
	if err != nil {
		t.Fatal(err)
	}
	email := uuid.NewV7().String() + "@example.com"
	registration, _ := authService(t, pool)
	id, err := registration.Register(ctx, email, "a sufficiently long password")
	if err != nil {
		t.Fatal(err)
	}
	cleanupUser(t, pool, id)
	verifyTestUser(t, pool, id)
	result, err := service.Login(ctx, email, "a sufficiently long password")
	if !errors.Is(err, failure) || result != (auth.LoginResult{}) {
		t.Fatal("tokens returned from aborted transaction")
	}
	var count int
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*) FROM identity.sessions WHERE user_id = $1`,
		id,
	).Scan(&count); err != nil ||
		count != 0 {
		t.Fatalf("aborted login sessions=%d err=%v", count, err)
	}
}
