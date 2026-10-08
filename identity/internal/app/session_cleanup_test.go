package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"
)

type cleanerFunc func(context.Context, time.Time, int) (int64, error)

func (f cleanerFunc) DeleteExpired(ctx context.Context, before time.Time, limit int) (int64, error) {
	return f(ctx, before, limit)
}

func TestSessionCleanupBatches(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		counts []int64
		err    error
	}{
		{
			name:   "empty",
			counts: []int64{0},
			err:    nil,
		},
		{
			name:   "partial batch",
			counts: []int64{3},
			err:    nil,
		},
		{
			name:   "multiple batches",
			counts: []int64{10, 10, 2},
			err:    nil,
		},
		{
			name:   "storage failure",
			counts: []int64{0},
			err:    errors.New("database unavailable"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			started := time.Now().UTC()
			calls := 0
			var firstCutoff time.Time
			a := &App{
				log: zap.NewNop(),
			}
			a.sessions = cleanerFunc(func(ctx context.Context, before time.Time, limit int) (int64, error) {
				if limit != 10 || before.Before(started.Add(-time.Hour)) || before.After(time.Now().UTC().Add(-time.Hour)) {
					t.Fatal("incorrect cleanup grace or batch")
				}
				deadline, ok := ctx.Deadline()
				if !ok || deadline.After(started.Add(5*time.Second+100*time.Millisecond)) {
					t.Fatal("cleanup has no bounded budget")
				}
				if calls == 0 {
					firstCutoff = before
				} else if !before.Equal(firstCutoff) {
					t.Fatal("cutoff moved between batches")
				}
				if calls >= len(tc.counts) {
					t.Fatal("cleanup failed to stop")
				}
				count := tc.counts[calls]
				calls++
				return count, tc.err
			})
			a.cleanExpiredSessions(t.Context())
			if calls != len(tc.counts) {
				t.Fatalf("cleanup calls=%d", calls)
			}
		})
	}
}

func TestSessionCleanupLifecycle(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered := make(chan struct{})
	a := &App{
		log: zap.NewNop(),
		sessions: cleanerFunc(func(ctx context.Context, _ time.Time, _ int) (int64, error) {
			close(entered)
			<-ctx.Done()
			return 0, ctx.Err()
		}),
	}
	done := make(chan struct{})
	go func() { defer close(done); a.runSessionCleanup(ctx) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not start immediately")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not stop on cancellation")
	}
}
