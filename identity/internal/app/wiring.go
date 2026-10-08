package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	"github.com/horizoonn/relay/platform/pkg/httpmiddleware"
	"github.com/horizoonn/relay/platform/pkg/postgres"
	"github.com/horizoonn/relay/platform/pkg/security/accessjwt"
	"go.uber.org/zap"

	smtpclient "github.com/horizoonn/relay/identity/internal/client/smtp"
	"github.com/horizoonn/relay/identity/internal/config"
	"github.com/horizoonn/relay/identity/internal/mailcipher"
	"github.com/horizoonn/relay/identity/internal/password"
	tokenrepo "github.com/horizoonn/relay/identity/internal/repository/postgres/accounttoken"
	emailrepo "github.com/horizoonn/relay/identity/internal/repository/postgres/emailjob"
	sessionrepo "github.com/horizoonn/relay/identity/internal/repository/postgres/session"
	userrepo "github.com/horizoonn/relay/identity/internal/repository/postgres/user"
	identityhttp "github.com/horizoonn/relay/identity/internal/transport/http/identityv1"
	"github.com/horizoonn/relay/identity/internal/usecase/account"
	"github.com/horizoonn/relay/identity/internal/usecase/auth"
	"github.com/horizoonn/relay/identity/internal/usecase/email"
	"github.com/horizoonn/relay/identity/internal/usecase/session"
)

//nolint:cyclop // Straight-line composition keeps dependency ownership and startup cleanup visible.
func New(
	ctx context.Context,
	cfg config.Config,
	log *zap.Logger,
) (application *App, initErr error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate Identity config: %w", err)
	}
	if log == nil {
		return nil, errors.New("logger is required")
	}
	key, err := accessjwt.LoadPrivateKey(cfg.Signing.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load Identity signing key: %w", err)
	}
	issuer, err := accessjwt.NewIssuer(cfg.Signing.KeyID, key)
	if err != nil {
		return nil, fmt.Errorf("initialize access issuer: %w", err)
	}
	verifier, err := newAccessVerifier(cfg.Signing, key)
	if err != nil {
		return nil, fmt.Errorf("initialize access verifier: %w", err)
	}
	pool, err := postgres.NewPool(ctx, cfg.Postgres)
	if err != nil {
		return nil, fmt.Errorf("initialize Identity PostgreSQL: %w", err)
	}
	client, limiter, err := newRedisLimiter(ctx, cfg.Redis, cfg.RateLimit, log)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("initialize Identity rate limiter: %w", err)
	}
	closeResources := true
	defer func() {
		if closeResources {
			pool.Close()
			if closeErr := client.Close(); closeErr != nil {
				initErr = errors.Join(initErr, fmt.Errorf("close Redis after initialization failure: %w", closeErr))
			}
		}
	}()
	tx := postgres.NewTxManager(pool)
	users := userrepo.NewRepository(tx.Executor, 5*time.Second)
	sessions := sessionrepo.NewRepository(tx.Executor, 5*time.Second)
	tokens := tokenrepo.NewRepository(tx.Executor, 5*time.Second)
	jobs := emailrepo.NewRepository(tx.Executor, 5*time.Second)

	cipher, err := mailcipher.New([]byte(cfg.Mail.EncryptionKey))
	if err != nil {
		return nil, fmt.Errorf("initialize email payload encryption: %w", err)
	}
	requests, err := email.NewRequests(jobs, cipher, limiter)
	if err != nil {
		return nil, fmt.Errorf("initialize account email requests: %w", err)
	}
	passwords, err := password.NewHasher(cfg.App.MaxParallelPasswords)
	if err != nil {
		return nil, fmt.Errorf("initialize password hasher: %w", err)
	}
	authService, err := auth.NewService(ctx, users, sessions, tx, issuer, passwords, limiter, requests)
	if err != nil {
		return nil, fmt.Errorf("initialize authentication service: %w", err)
	}
	sessionService, err := session.NewService(users, sessions, tx, issuer)
	if err != nil {
		return nil, fmt.Errorf("initialize session service: %w", err)
	}
	accountService, err := account.NewService(users, tokens, sessions, tx, passwords, requests)
	if err != nil {
		return nil, fmt.Errorf("initialize account service: %w", err)
	}

	sender, err := smtpclient.New(cfg.Mail.SMTP(), log)
	if err != nil {
		return nil, fmt.Errorf("initialize SMTP sender: %w", err)
	}
	delivery, err := email.NewDelivery(jobs, users, tokens, tx, cipher, sender, cfg.HTTP.AllowedOrigin)
	if err != nil {
		return nil, fmt.Errorf("initialize email delivery: %w", err)
	}

	cursors, err := identityhttp.NewCursorCodec([]byte(cfg.HTTP.CursorSigningKey))
	if err != nil {
		return nil, fmt.Errorf("initialize session cursor codec: %w", err)
	}
	handler, err := identityhttp.NewHandler(
		authService,
		sessionService,
		verifier,
		cursors,
		log,
		limiter,
		requests,
		accountService,
	)
	if err != nil {
		return nil, fmt.Errorf("initialize Identity HTTP handler: %w", err)
	}
	trusted := make([]netip.Prefix, 0, len(cfg.HTTP.TrustedProxyPrefixes))
	for _, raw := range cfg.HTTP.TrustedProxyPrefixes {
		trusted = append(trusted, netip.MustParsePrefix(raw))
	}
	api, err := identityhttp.NewServer(handler, cfg.HTTP.AllowedOrigin, trusted)
	if err != nil {
		return nil, fmt.Errorf("initialize Identity HTTP server: %w", err)
	}
	a := &App{
		log:             log,
		pool:            pool,
		redis:           client,
		sessions:        sessions,
		tokens:          tokens,
		email:           delivery,
		emailWorkers:    cfg.App.EmailWorkers,
		shutdownTimeout: cfg.App.ShutdownTimeout,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", identityhttp.Healthz)
	mux.HandleFunc("GET /readyz", identityhttp.Readyz(a.checkReadiness))
	mux.Handle("/", httpmiddleware.Deadline(api, 15*time.Second))
	a.server = &http.Server{
		Addr:              cfg.HTTP.Address,
		Handler:           httpmiddleware.AccessLog(log, mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	closeResources = false
	return a, nil
}
