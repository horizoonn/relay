package app

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/horizoonn/relay/platform/pkg/logger"
	"go.uber.org/zap"
	"golang.org/x/time/rate"

	smtpclient "github.com/horizoonn/relay/identity/internal/client/smtp"
)

type emailDelivery interface {
	DeliverOne(context.Context) (bool, error)
}

func (a *App) runEmailDelivery(ctx context.Context) {
	warning := rate.NewLimiter(rate.Every(time.Minute), 1)
	var workers sync.WaitGroup
	for range a.emailWorkers {
		workers.Go(func() {
			a.runEmailWorker(ctx, warning)
		})
	}
	workers.Wait()
}

func (a *App) runEmailWorker(ctx context.Context, warning *rate.Limiter) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		for range 10 {
			if ctx.Err() != nil {
				return
			}
			operation, cancel := context.WithTimeout(ctx, 10*time.Second)
			worked, err := a.email.DeliverOne(operation)
			cancel()
			if err != nil && ctx.Err() == nil && warning.Allow() {
				fields := logger.ErrorFields(err)
				var delivery *smtpclient.DeliveryError
				if errors.As(err, &delivery) {
					fields = []zap.Field{
						zap.String("operation", "smtp_"+delivery.Operation),
						zap.String("error_kind", delivery.Kind),
						zap.Bool("permanent_failure", delivery.Permanent()),
					}
				}
				a.log.Warn("Identity email delivery failed", fields...)
			}
			if !worked {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
