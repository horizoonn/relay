package app

import (
	"context"
	"time"

	"github.com/horizoonn/relay/platform/pkg/logger"
	"go.uber.org/zap"
)

const (
	receiptCleanupInterval  = 5 * time.Minute
	receiptCleanupBatchSize = 1000
	receiptCleanupGrace     = time.Hour
)

type receiptCleaner interface {
	DeleteExpiredReceipts(context.Context, time.Time, int) (int64, error)
}

func (a *App) runReceiptCleanup(ctx context.Context) {
	ticker := time.NewTicker(receiptCleanupInterval)
	defer ticker.Stop()
	for {
		a.cleanExpiredReceipts(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (a *App) cleanExpiredReceipts(ctx context.Context) {
	var total int64
	cutoff := time.Now().Add(-receiptCleanupGrace)
	for ctx.Err() == nil {
		deleted, err := a.receipts.DeleteExpiredReceipts(ctx, cutoff, receiptCleanupBatchSize)
		if err != nil {
			if ctx.Err() == nil {
				a.log.Error("delete expired Capture receipts", logger.ErrorFields(err)...)
			}
			return
		}
		total += deleted
		if deleted < receiptCleanupBatchSize {
			break
		}
	}
	if total > 0 {
		a.log.Info("expired Capture receipts deleted", zap.Int64("count", total))
	}
}
