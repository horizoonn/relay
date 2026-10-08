package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/horizoonn/relay/platform/pkg/httpmiddleware"
	"github.com/horizoonn/relay/platform/pkg/postgres"
	"go.uber.org/zap"

	"github.com/horizoonn/relay/content/internal/config"
	contentrepo "github.com/horizoonn/relay/content/internal/repository/postgres"
	contenthttp "github.com/horizoonn/relay/content/internal/transport/http/contentv1"
	"github.com/horizoonn/relay/content/internal/usecase/capture"
	"github.com/horizoonn/relay/content/internal/usecase/collection"
	"github.com/horizoonn/relay/content/internal/usecase/item"
	"github.com/horizoonn/relay/content/internal/usecase/search"
)

func New(
	ctx context.Context,
	cfg config.Config,
	log *zap.Logger,
) (application *App, initErr error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate Content config: %w", err)
	}
	if log == nil {
		return nil, errors.New("logger is required")
	}
	verifier, err := newAccessVerifier(cfg.Access)
	if err != nil {
		return nil, fmt.Errorf("initialize access verifier: %w", err)
	}
	pool, err := postgres.NewPool(ctx, cfg.Postgres)
	if err != nil {
		return nil, fmt.Errorf("initialize Content PostgreSQL: %w", err)
	}
	client, limiter, err := newRedisLimiter(ctx, cfg.Redis, cfg.RateLimit, log)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("initialize Content rate limiter: %w", err)
	}
	closePool := true
	defer func() {
		if closePool {
			pool.Close()
			if closeErr := client.Close(); closeErr != nil {
				initErr = errors.Join(initErr, fmt.Errorf("close Redis after initialization failure: %w", closeErr))
			}
		}
	}()

	tx := postgres.NewTxManager(pool)
	repo := contentrepo.NewRepository(tx.Executor, 5*time.Second)
	captureService := capture.NewService(repo, repo, tx)
	itemService := item.NewService(repo, tx)
	collectionService := collection.NewService(repo)
	searchService := search.NewService(repo)
	cursors, err := contenthttp.NewCursorCodec([]byte(cfg.HTTP.CursorKey))
	if err != nil {
		return nil, fmt.Errorf("initialize cursor codec: %w", err)
	}
	handler, err := contenthttp.NewHandler(
		captureService, itemService, collectionService, searchService, cursors, log,
	)
	if err != nil {
		return nil, fmt.Errorf("initialize Content HTTP handler: %w", err)
	}
	api, err := contenthttp.NewServer(handler, verifier, cfg.HTTP.AllowedOrigin, limiter)
	if err != nil {
		return nil, fmt.Errorf("initialize Content HTTP server: %w", err)
	}

	a := &App{
		log:             log,
		pool:            pool,
		redis:           client,
		receipts:        repo,
		shutdownTimeout: cfg.App.ShutdownTimeout,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", contenthttp.Healthz)
	mux.HandleFunc("GET /readyz", contenthttp.Readyz(a.checkReadiness))
	mux.Handle("/", httpmiddleware.Deadline(api, 15*time.Second))
	a.server = &http.Server{
		Addr:              cfg.HTTP.Address,
		Handler:           httpmiddleware.AccessLog(log, mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	closePool = false
	return a, nil
}
