package app

import (
	"context"
	"time"

	"github.com/horizoonn/relay/platform/pkg/logger"
	"go.uber.org/zap"
)

const (
	sessionCleanupInterval  = 5 * time.Minute
	sessionCleanupGrace     = time.Hour
	sessionCleanupBatchSize = 10
	sessionCleanupBudget    = 5 * time.Second
)

type sessionCleaner interface {
	DeleteExpired(context.Context, time.Time, int) (int64, error)
}

func (a *App) runSessionCleanup(ctx context.Context) {
	ticker := time.NewTicker(sessionCleanupInterval)
	defer ticker.Stop()
	for {
		a.cleanExpiredSessions(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (a *App) cleanExpiredSessions(ctx context.Context) {
	cycle, cancel := context.WithTimeout(ctx, sessionCleanupBudget)
	defer cancel()
	cutoff := time.Now().UTC().Add(-sessionCleanupGrace)
	if a.tokens != nil {
		for cycle.Err() == nil {
			deleted, err := a.tokens.DeleteExpired(cycle, time.Now().UTC(), 100)
			if err != nil {
				if ctx.Err() == nil {
					a.log.Error("expired account token cleanup failed", logger.ErrorFields(err)...)
				}
				break
			}
			if deleted < 100 {
				break
			}
		}
	}
	var total int64
	for cycle.Err() == nil {
		deleted, err := a.sessions.DeleteExpired(cycle, cutoff, sessionCleanupBatchSize)
		if err != nil {
			if ctx.Err() == nil {
				a.log.Error("expired session cleanup failed", append([]zap.Field{
					zap.Int64("deleted_sessions", total),
				}, logger.ErrorFields(err)...)...)
			}
			return
		}
		total += deleted
		if deleted < sessionCleanupBatchSize {
			break
		}
	}
	if total > 0 {
		a.log.Info("expired sessions deleted", zap.Int64("count", total))
	}
}
