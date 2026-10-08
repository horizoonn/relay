package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type App struct {
	log               *zap.Logger
	server            *http.Server
	pool              *pgxpool.Pool
	redis             *redis.Client
	receipts          receiptCleaner
	shutdownTimeout   time.Duration
	acceptingRequests atomic.Bool
	listenAddress     atomic.Value
}

func (a *App) HTTPAddress() string {
	address, _ := a.listenAddress.Load().(string)
	return address
}

func (a *App) Run(ctx context.Context) (runErr error) {
	defer a.pool.Close()
	defer func() {
		if err := a.redis.Close(); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("close Redis: %w", err))
		}
	}()

	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", a.server.Addr)
	if err != nil {
		return fmt.Errorf("listen HTTP: %w", err)
	}
	a.listenAddress.Store(listener.Addr().String())
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- a.server.Serve(listener)
	}()
	if a.receipts != nil {
		cleanupCtx, stopCleanup := context.WithCancel(ctx)
		cleanupDone := make(chan struct{})
		go func() {
			defer close(cleanupDone)
			a.runReceiptCleanup(cleanupCtx)
		}()
		defer func() {
			stopCleanup()
			<-cleanupDone
		}()
	}
	a.acceptingRequests.Store(true)
	a.log.Info("Content HTTP server started", zap.String("address", listener.Addr().String()))

	select {
	case err := <-serveErr:
		a.acceptingRequests.Store(false)
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve HTTP: %w", err)
	case <-ctx.Done():
		a.acceptingRequests.Store(false)
	}

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.shutdownTimeout)
	defer cancel()
	if err := a.server.Shutdown(shutdownCtx); err != nil {
		if closeErr := a.server.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close HTTP: %w", closeErr))
		}
		return fmt.Errorf("shutdown HTTP: %w", err)
	}
	if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve HTTP: %w", err)
	}
	return nil
}

func (a *App) checkReadiness(ctx context.Context) error {
	if !a.acceptingRequests.Load() {
		return errors.New("application is not accepting requests")
	}
	if err := a.pool.Ping(ctx); err != nil {
		return fmt.Errorf("check PostgreSQL readiness: %w", err)
	}
	return nil
}
