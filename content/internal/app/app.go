package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type App struct {
	log             *slog.Logger
	server          *http.Server
	pool            *pgxpool.Pool
	identity        Identity
	receipts        receiptCleaner
	shutdownTimeout time.Duration
	ready           atomic.Bool
	listenAddress   atomic.Value
}

func (a *App) Address() string {
	address, _ := a.listenAddress.Load().(string)
	return address
}

func (a *App) Run(ctx context.Context) error {
	defer a.pool.Close()

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
	a.ready.Store(true)
	a.log.Info("Content HTTP server started", "address", listener.Addr().String())

	select {
	case err := <-serveErr:
		a.ready.Store(false)
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve HTTP: %w", err)
	case <-ctx.Done():
		a.ready.Store(false)
	}

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.shutdownTimeout)
	defer cancel()
	if err := a.server.Shutdown(shutdownCtx); err != nil {
		_ = a.server.Close()
		return fmt.Errorf("shutdown HTTP: %w", err)
	}
	if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve HTTP: %w", err)
	}
	return nil
}

func (a *App) health(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (a *App) readiness(w http.ResponseWriter, r *http.Request) {
	if !a.ready.Load() {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()
	if err := a.pool.Ping(ctx); err != nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	if err := a.identity.Check(r.Context()); err != nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	if status < http.StatusOK {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func (w *statusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (a *App) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		response := &statusWriter{
			ResponseWriter: w,
		}
		next.ServeHTTP(response, r)
		status := response.status
		if status == 0 {
			status = http.StatusOK
		}
		a.log.InfoContext(r.Context(), "HTTP request",
			"method", r.Method,
			"status", status,
			"request_id", response.Header().Get("X-Request-ID"),
			"duration", time.Since(started),
		)
	})
}
