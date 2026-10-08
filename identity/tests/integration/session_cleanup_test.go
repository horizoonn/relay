//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/horizoonn/relay/identity/internal/domain"
	sessioncase "github.com/horizoonn/relay/identity/internal/usecase/session"
)

func TestSessionCleanupBoundary(t *testing.T) {
	f, ctx := lifecycle(t)
	cutoff := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	for _, tc := range []struct {
		name    string
		delta   time.Duration
		deleted bool
	}{
		{
			name:    "before cutoff",
			delta:   -time.Microsecond,
			deleted: true,
		}, {
			name:    "at cutoff",
			delta:   0,
			deleted: true,
		}, {
			name:    "grace period",
			delta:   time.Microsecond,
			deleted: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := addSession(t, f, ctx, cutoff.Add(-time.Hour), cutoff.Add(tc.delta))
			count, err := f.sessions.DeleteExpired(ctx, cutoff, 10)
			if err != nil {
				t.Fatal(err)
			}
			want := int64(0)
			if tc.deleted {
				want = 1
			}
			if count != want {
				t.Fatalf("deleted=%d want=%d", count, want)
			}
			_, err = f.sessions.Get(ctx, f.current.UserID, value.ID)
			if tc.deleted && !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("expired parent remains: %v", err)
			}
			if !tc.deleted && err != nil {
				t.Fatalf("grace parent lost: %v", err)
			}
			var credentials int
			if err := f.pool.QueryRow(
				ctx,
				`SELECT count(*) FROM identity.refresh_credentials WHERE session_id=$1`,
				value.ID,
			).Scan(&credentials); err != nil {
				t.Fatal(err)
			}
			expected := 1
			if tc.deleted {
				expected = 0
			}
			if credentials != expected {
				t.Fatalf("credentials=%d want=%d", credentials, expected)
			}
		})
	}
}

func TestCleanupSkipsLockedParentsAndLimitsBatch(t *testing.T) {
	f, ctx := lifecycle(t)
	cutoff := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	locked := addSession(t, f, ctx, cutoff.Add(-time.Hour), cutoff)
	for range 3 {
		addSession(t, f, ctx, cutoff.Add(-time.Hour), cutoff)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, lockErr := tx.Exec(ctx, `SELECT id FROM identity.sessions WHERE id=$1 FOR UPDATE`, locked.ID); lockErr != nil {
		t.Fatal(lockErr)
	}
	short, cancel := context.WithTimeout(ctx, time.Second)
	count, err := f.sessions.DeleteExpired(short, cutoff, 2)
	cancel()
	if err != nil || count != 2 {
		t.Fatalf("locked row blocked cleanup: count=%d error=%v", count, err)
	}
	if _, err = f.sessions.Get(ctx, f.current.UserID, locked.ID); err != nil {
		t.Fatal("locked parent was deleted")
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	count, err = f.sessions.DeleteExpired(ctx, cutoff, 2)
	if err != nil || count != 2 {
		t.Fatalf("remaining cleanup: %d %v", count, err)
	}
}

func TestConcurrentSessionCleanup(t *testing.T) {
	f, ctx := lifecycle(t)
	cutoff := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	for range 12 {
		addSession(t, f, ctx, cutoff.Add(-time.Hour), cutoff)
	}
	start := make(chan struct{})
	type result struct {
		count int64
		err   error
	}
	done := make(chan result, 2)
	for range 2 {
		go func() {
			<-start
			count, err := f.sessions.DeleteExpired(ctx, cutoff, 10)
			done <- result{
				count,
				err,
			}
		}()
	}
	close(start)
	var total int64
	for range 2 {
		result := <-done
		if result.err != nil {
			t.Fatal(result.err)
		}
		total += result.count
	}
	remaining, err := f.sessions.DeleteExpired(ctx, cutoff, 10)
	if err != nil || total+remaining != 12 {
		t.Fatalf("concurrent deletion total=%d remaining=%d error=%v", total, remaining, err)
	}
	if _, err := f.sessions.Get(ctx, f.current.UserID, f.current.ID); err != nil {
		t.Fatal("active session lost")
	}
}

func TestCleanupPreservesRefreshReplay(t *testing.T) {
	f, ctx := lifecycle(t)
	rotated, err := f.service.Refresh(ctx, f.rawRefresh, f.rawCSRF)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(
		ctx,
		`UPDATE identity.refresh_credentials SET used_at=now()-interval '11 seconds' WHERE session_id=$1 AND generation=0`,
		f.current.ID,
	); err != nil {
		t.Fatal(err)
	}
	if count, err := f.sessions.DeleteExpired(ctx, time.Now().UTC().Add(-time.Hour), 10); err != nil || count != 0 {
		t.Fatalf("active family cleanup: %d %v", count, err)
	}
	if _, err := f.service.Refresh(ctx, f.rawRefresh, f.rawCSRF); !errors.Is(err, sessioncase.ErrUnauthenticated) {
		t.Fatalf("late replay: %v", err)
	}
	if _, err := f.service.Refresh(ctx, rotated.RefreshToken, f.rawCSRF); !errors.Is(err, sessioncase.ErrUnauthenticated) {
		t.Fatal("cleanup lost replay history")
	}
}

func TestCleanupCascadesLongRefreshHistory(t *testing.T) {
	f, ctx := lifecycle(t)
	cutoff := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	value := addSession(t, f, ctx, cutoff.Add(-time.Hour), cutoff)
	if _, err := f.pool.Exec(
		ctx,
		`UPDATE identity.refresh_credentials SET used_at=$2 WHERE session_id=$1`,
		value.ID,
		cutoff,
	); err != nil {
		t.Fatal(err)
	}
	const insertHistory = `
        INSERT INTO identity.refresh_credentials (token_hash, session_id, generation, created_at, expires_at, used_at)
        SELECT sha256(convert_to($1::uuid::text || ':' || n::text, 'UTF8')), $1, n, $2, $3, $3
        FROM generate_series(1, 8640) AS n
    `
	if _, err := f.pool.Exec(ctx, insertHistory, value.ID, value.CreatedAt, value.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := f.pool.QueryRow(
		ctx,
		`SELECT count(*) FROM identity.refresh_credentials WHERE session_id=$1`,
		value.ID,
	).Scan(&count); err != nil ||
		count != 8641 {
		t.Fatalf("history fixture: %d %v", count, err)
	}
	if deleted, err := f.sessions.DeleteExpired(ctx, cutoff, 1); err != nil || deleted != 1 {
		t.Fatalf("large family cleanup: %d %v", deleted, err)
	}
	if err := f.pool.QueryRow(
		ctx,
		`SELECT count(*) FROM identity.refresh_credentials WHERE session_id=$1`,
		value.ID,
	).Scan(&count); err != nil ||
		count != 0 {
		t.Fatalf("cascade left history: %d %v", count, err)
	}
}

func TestCleanupRollback(t *testing.T) {
	f, ctx := lifecycle(t)
	cutoff := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	value := addSession(t, f, ctx, cutoff.Add(-time.Hour), cutoff)
	blocker, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(context.WithoutCancel(ctx)) }()
	if _, err = blocker.Exec(
		ctx,
		`SELECT token_hash FROM identity.refresh_credentials WHERE session_id=$1 FOR UPDATE`,
		value.ID,
	); err != nil {
		t.Fatal(err)
	}
	bounded, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	deleted, err := f.sessions.DeleteExpired(bounded, cutoff, 10)
	cancel()
	if err == nil || deleted != 0 {
		t.Fatal("blocked cascade ignored timeout")
	}
	if _, readErr := f.sessions.Get(ctx, f.current.UserID, value.ID); readErr != nil {
		t.Fatal("failed cascade deleted parent")
	}
	if err = blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if deleted, err = f.sessions.DeleteExpired(ctx, cutoff, 10); err != nil || deleted != 1 {
		t.Fatalf("cleanup did not recover: %d %v", deleted, err)
	}
}
