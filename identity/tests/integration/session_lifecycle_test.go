//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/platform/pkg/postgres"
	"github.com/horizoonn/relay/platform/pkg/security/accessjwt"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/horizoonn/relay/identity/internal/domain"
	sessionrepo "github.com/horizoonn/relay/identity/internal/repository/postgres/session"
	userrepo "github.com/horizoonn/relay/identity/internal/repository/postgres/user"
	"github.com/horizoonn/relay/identity/internal/secret"
	sessioncase "github.com/horizoonn/relay/identity/internal/usecase/session"
)

type lifecycleFixture struct {
	pool       *pgxpool.Pool
	service    *sessioncase.Service
	sessions   *sessionrepo.Repository
	verifier   *accessjwt.Verifier
	issuer     *accessjwt.Issuer
	current    domain.Session
	rawRefresh string
	rawCSRF    string
}

func lifecycle(t *testing.T) (lifecycleFixture, context.Context) {
	t.Helper()
	pool, ctx := testPool(t)
	tx := postgres.NewTxManager(pool)
	users := userrepo.NewRepository(tx.Executor, 5*time.Second)
	sessions := sessionrepo.NewRepository(tx.Executor, 5*time.Second)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := accessjwt.NewIssuer("lifecycle", private)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := accessjwt.NewVerifier(map[string]ed25519.PublicKey{"lifecycle": public})
	if err != nil {
		t.Fatal(err)
	}
	service, err := sessioncase.NewService(users, sessions, tx, issuer)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	user, err := domain.NewUser(uuid.NewV7().String()+"@example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	cleanupUser(t, pool, user.ID)
	if createErr := users.Create(ctx, user, "unused-by-refresh"); createErr != nil {
		t.Fatal(createErr)
	}
	verifyTestUser(t, pool, user.ID)
	csrf, err := secret.Generate()
	if err != nil {
		t.Fatal(err)
	}
	csrfHash, err := secret.Digest(csrf)
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := secret.Generate()
	if err != nil {
		t.Fatal(err)
	}
	refreshHash, err := secret.Digest(refresh)
	if err != nil {
		t.Fatal(err)
	}
	current, err := domain.NewSession(user.ID, csrfHash, now, now.Add(domain.MaxSessionLifetime))
	if err != nil {
		t.Fatal(err)
	}
	if err := sessions.Create(ctx, current, refreshHash); err != nil {
		t.Fatal(err)
	}
	return lifecycleFixture{
		pool:       pool,
		service:    service,
		sessions:   sessions,
		verifier:   verifier,
		issuer:     issuer,
		current:    current,
		rawRefresh: refresh,
		rawCSRF:    csrf,
	}, ctx
}

func TestRefreshRotationAndReplay(t *testing.T) {
	f, ctx := lifecycle(t)
	result, err := f.service.Refresh(ctx, f.rawRefresh, f.rawCSRF)
	if err != nil {
		t.Fatal(err)
	}
	if result.RefreshToken == f.rawRefresh || result.UserID != f.current.UserID || result.SessionID != f.current.ID ||
		!result.SessionExpiresAt.Equal(f.current.ExpiresAt) {
		t.Fatal("rotation changed identity or absolute expiry")
	}
	access, err := f.verifier.Verify(result.AccessToken)
	if err != nil || access.CSRFHash != f.current.CSRFHash {
		t.Fatal("invalid refreshed access")
	}
	oldHash, _ := secret.Digest(f.rawRefresh)
	old, err := f.sessions.GetRefreshCredential(ctx, oldHash)
	if err != nil || old.UsedAt == nil {
		t.Fatal("old refresh not consumed")
	}
	newHash, _ := secret.Digest(result.RefreshToken)
	next, err := f.sessions.GetRefreshCredential(ctx, newHash)
	if err != nil || next.Generation != 1 || next.UsedAt != nil || !next.ExpiresAt.Equal(old.ExpiresAt) {
		t.Fatal("incorrect next generation")
	}
	current, err := f.sessions.Get(ctx, f.current.UserID, f.current.ID)
	if err != nil || !current.LastSeenAt.After(f.current.LastSeenAt) {
		t.Fatal("refresh did not update activity")
	}
	if _, replayErr := f.service.Refresh(ctx, f.rawRefresh, f.rawCSRF); !errors.Is(
		replayErr, sessioncase.ErrRefreshConflict,
	) {
		t.Fatalf("early replay: %v", replayErr)
	}
	if _, updateErr := f.pool.Exec(
		ctx,
		`UPDATE identity.refresh_credentials SET used_at=now()-interval '11 seconds' WHERE token_hash=$1`,
		oldHash[:],
	); updateErr != nil {
		t.Fatal(updateErr)
	}
	if _, replayErr := f.service.Refresh(ctx, f.rawRefresh, f.rawCSRF); !errors.Is(
		replayErr, sessioncase.ErrUnauthenticated,
	) {
		t.Fatalf("late replay: %v", replayErr)
	}
	current, err = f.sessions.Get(ctx, f.current.UserID, f.current.ID)
	if err != nil || current.RevokedAt == nil {
		t.Fatal("late replay revocation was rolled back")
	}
	if _, err := f.service.Refresh(ctx, result.RefreshToken, f.rawCSRF); !errors.Is(err, sessioncase.ErrUnauthenticated) {
		t.Fatal("replay did not revoke the family")
	}
	if _, err := f.verifier.Verify(result.AccessToken); err != nil {
		t.Fatal("revocation unexpectedly changes an issued JWT")
	}
}

func TestConcurrentRefresh(t *testing.T) {
	f, ctx := lifecycle(t)
	race := newSessionLockRace(t, f)
	firstDone, secondDone := make(chan error, 1), make(chan error, 1)
	go func() { _, err := race.first.Refresh(ctx, f.rawRefresh, f.rawCSRF); firstDone <- err }()
	race.awaitFirst(t, ctx, firstDone)
	go func() { _, err := race.second.Refresh(ctx, f.rawRefresh, f.rawCSRF); secondDone <- err }()
	race.releaseAfterLockWait(t, ctx)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if err := <-secondDone; !errors.Is(err, sessioncase.ErrRefreshConflict) {
		t.Fatalf("concurrent refresh error=%v; want ErrRefreshConflict", err)
	}
	var total, current int
	if err := f.pool.QueryRow(
		ctx,
		`SELECT count(*), count(*) FILTER (WHERE used_at IS NULL) FROM identity.refresh_credentials WHERE session_id=$1`,
		f.current.ID,
	).Scan(
		&total,
		&current,
	); err != nil {
		t.Fatal(err)
	}
	if total != 2 || current != 1 {
		t.Fatal("concurrent refresh created multiple current credentials")
	}
}

func TestRefreshRejectsInvalidState(t *testing.T) {
	for _, tc := range []struct {
		name  string
		query string
		csrf  bool
		want  error
	}{
		{
			name:  "disabled",
			query: `UPDATE identity.users SET state='disabled' WHERE id=(SELECT user_id FROM identity.sessions WHERE id=$1)`,
			csrf:  false,
			want:  sessioncase.ErrUnauthenticated,
		},
		{
			name:  "revoked",
			query: `UPDATE identity.sessions SET revoked_at=now() WHERE id=$1`,
			csrf:  false,
			want:  sessioncase.ErrUnauthenticated,
		},
		{
			name:  "expired session",
			query: `UPDATE identity.sessions SET expires_at=now()-interval '1 second' WHERE id=$1`,
			csrf:  false,
			want:  sessioncase.ErrUnauthenticated,
		},
		{
			name:  "expired refresh",
			query: `UPDATE identity.refresh_credentials SET expires_at=now()-interval '1 second' WHERE session_id=$1`,
			csrf:  false,
			want:  sessioncase.ErrUnauthenticated,
		},
		{
			name:  "overflow",
			query: `UPDATE identity.refresh_credentials SET generation=9223372036854775807 WHERE session_id=$1`,
			csrf:  false,
			want:  domain.ErrInvalidRefreshCredential,
		},
		{
			name:  "wrong CSRF",
			query: "",
			csrf:  true,
			want:  sessioncase.ErrCSRF,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, ctx := lifecycle(t)
			if tc.query != "" {
				if _, err := f.pool.Exec(ctx, tc.query, f.current.ID); err != nil {
					t.Fatal(err)
				}
			}
			csrf := f.rawCSRF
			if tc.csrf {
				csrf, _ = secret.Generate()
			}
			result, err := f.service.Refresh(ctx, f.rawRefresh, csrf)
			if !errors.Is(err, tc.want) || result != (sessioncase.RefreshResult{}) {
				t.Fatalf("result leaked or wrong error: %v", err)
			}
			var count int
			if err := f.pool.QueryRow(
				ctx,
				`SELECT count(*) FROM identity.refresh_credentials WHERE session_id=$1 AND used_at IS NULL`,
				f.current.ID,
			).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 1 {
				t.Fatal("rejection consumed a refresh")
			}
		})
	}
}

type failingRefreshIssuer struct{}

func (failingRefreshIssuer) Issue(uuid.UUID, uuid.UUID, [32]byte, time.Time) (accessjwt.Token, error) {
	return accessjwt.Token{}, errors.New("signer unavailable")
}

func TestRefreshRollbackAndAbsoluteExpiry(t *testing.T) {
	f, ctx := lifecycle(t)
	tx := postgres.NewTxManager(f.pool)
	failed, err := sessioncase.NewService(
		userrepo.NewRepository(tx.Executor, time.Second),
		sessionrepo.NewRepository(tx.Executor, time.Second),
		tx,
		failingRefreshIssuer{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result, refreshErr := failed.Refresh(ctx, f.rawRefresh, f.rawCSRF); refreshErr == nil ||
		result != (sessioncase.RefreshResult{}) {
		t.Fatal("failed signing returned credentials")
	}
	var count int
	if readErr := f.pool.QueryRow(
		ctx,
		`SELECT count(*) FROM identity.refresh_credentials WHERE session_id=$1`,
		f.current.ID,
	).Scan(&count); readErr != nil ||
		count != 1 {
		t.Fatal("failed signing committed rotation")
	}
	expires := time.Now().UTC().Add(time.Minute).Truncate(time.Microsecond)
	if _, updateErr := f.pool.Exec(
		ctx,
		`UPDATE identity.sessions SET expires_at=$2 WHERE id=$1`,
		f.current.ID,
		expires,
	); updateErr != nil {
		t.Fatal(updateErr)
	}
	if _, updateErr := f.pool.Exec(
		ctx,
		`UPDATE identity.refresh_credentials SET expires_at=$2 WHERE session_id=$1`,
		f.current.ID,
		expires,
	); updateErr != nil {
		t.Fatal(updateErr)
	}
	result, err := f.service.Refresh(ctx, f.rawRefresh, f.rawCSRF)
	if err != nil || !result.SessionExpiresAt.Equal(expires) || result.AccessExpiresAt.After(expires) {
		t.Fatalf("absolute expiry extended: %v", err)
	}
}

func TestLogoutAndRefreshRace(t *testing.T) {
	for _, tt := range []struct {
		name         string
		refreshFirst bool
	}{
		{"refresh commits before logout", true}, {"logout commits before refresh", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f, ctx := lifecycle(t)
			race := newSessionLockRace(t, f)
			refreshed, loggedOut := make(chan error, 1), make(chan error, 1)
			refresh := func(service *sessioncase.Service) {
				_, err := service.Refresh(ctx, f.rawRefresh, f.rawCSRF)
				refreshed <- err
			}
			logout := func(service *sessioncase.Service) { loggedOut <- service.Logout(ctx, f.rawRefresh, f.rawCSRF) }
			if tt.refreshFirst {
				go refresh(race.first)
				race.awaitFirst(t, ctx, refreshed)
				go logout(race.second)
			} else {
				go logout(race.first)
				race.awaitFirst(t, ctx, loggedOut)
				go refresh(race.second)
			}
			race.releaseAfterLockWait(t, ctx)
			if err := <-loggedOut; err != nil {
				t.Fatal(err)
			}
			refreshErr := <-refreshed
			if tt.refreshFirst {
				if refreshErr != nil {
					t.Fatal(refreshErr)
				}
			} else if !errors.Is(refreshErr, sessioncase.ErrUnauthenticated) {
				t.Fatalf("refresh after logout: %v", refreshErr)
			}
			current, err := f.sessions.Get(ctx, f.current.UserID, f.current.ID)
			if err != nil {
				t.Fatal(err)
			}
			if current.RevokedAt == nil {
				t.Fatal("racing refresh undid logout")
			}
			if _, err := f.service.Refresh(ctx, f.rawRefresh, f.rawCSRF); !errors.Is(err, sessioncase.ErrUnauthenticated) {
				t.Fatalf("refresh accepted after logout: %v", err)
			}
			if err := f.service.Logout(ctx, f.rawRefresh, f.rawCSRF); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLogoutCSRFAndUnknownCredential(t *testing.T) {
	f, ctx := lifecycle(t)
	wrong, _ := secret.Generate()
	if err := f.service.Logout(ctx, f.rawRefresh, wrong); !errors.Is(err, sessioncase.ErrCSRF) {
		t.Fatal("logout ignored CSRF")
	}
	if _, err := f.service.Refresh(ctx, wrong, f.rawCSRF); !errors.Is(err, sessioncase.ErrUnauthenticated) {
		t.Fatal("unknown refresh accepted")
	}
	if err := f.service.Logout(ctx, wrong, f.rawCSRF); err != nil {
		t.Fatal("unknown logout failed")
	}
	if err := f.service.Logout(ctx, "", ""); err != nil {
		t.Fatal("empty logout failed")
	}
	current, err := f.sessions.Get(ctx, f.current.UserID, f.current.ID)
	if err != nil || current.RevokedAt != nil {
		t.Fatal("unknown credential revoked another session")
	}
}
