package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	platformpostgres "github.com/horizoonn/relay/platform/pkg/postgres"

	"github.com/horizoonn/relay/content/internal/auth"
	"github.com/horizoonn/relay/content/internal/config"
	contentrepo "github.com/horizoonn/relay/content/internal/repository/postgres"
	contenthttp "github.com/horizoonn/relay/content/internal/transport/http/contentv1"
	"github.com/horizoonn/relay/content/internal/usecase/capture"
	"github.com/horizoonn/relay/content/internal/usecase/collection"
	"github.com/horizoonn/relay/content/internal/usecase/item"
	"github.com/horizoonn/relay/content/internal/usecase/search"
)

type Identity interface {
	auth.Authenticator
	Check(context.Context) error
}

func New(
	ctx context.Context,
	cfg config.Config,
	log *slog.Logger,
	identity Identity,
) (*App, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate Content config: %w", err)
	}
	if log == nil || identity == nil {
		return nil, errors.New("logger and Identity client are required")
	}
	pool, err := platformpostgres.NewPool(ctx, cfg.Postgres)
	if err != nil {
		return nil, fmt.Errorf("initialize Content PostgreSQL: %w", err)
	}
	closePool := true
	defer func() {
		if closePool {
			pool.Close()
		}
	}()

	tx := platformpostgres.NewTxManager(pool)
	repo := contentrepo.NewRepository(tx.Executor, 5*time.Second)
	captureService := capture.NewService(repo, repo, tx)
	itemService := item.NewService(repo, tx)
	collectionService := collection.NewService(repo)
	searchService := search.NewService(repo)
	cursors, err := contenthttp.NewCursorCodec([]byte(cfg.HTTP.CursorKey))
	if err != nil {
		return nil, fmt.Errorf("initialize cursor codec: %w", err)
	}
	handler, err := contenthttp.NewHandler(captureService, itemService, collectionService, searchService, cursors, log)
	if err != nil {
		return nil, fmt.Errorf("initialize Content HTTP handler: %w", err)
	}
	api, err := contenthttp.NewServer(handler, identity, cfg.HTTP.AllowedOrigin)
	if err != nil {
		return nil, fmt.Errorf("initialize Content HTTP server: %w", err)
	}

	a := &App{
		log:             log.With("service", "content"),
		pool:            pool,
		identity:        identity,
		receipts:        repo,
		shutdownTimeout: cfg.App.ShutdownTimeout,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.health)
	mux.HandleFunc("GET /readyz", a.readiness)
	mux.Handle("/", api)
	a.server = &http.Server{
		Addr:              cfg.HTTP.Address,
		Handler:           a.logRequests(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	closePool = false
	return a, nil
}
