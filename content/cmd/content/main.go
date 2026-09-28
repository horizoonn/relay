package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/horizoonn/relay/content/internal/app"
	identityclient "github.com/horizoonn/relay/content/internal/client/identity"
	"github.com/horizoonn/relay/content/internal/config"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load Content config: %w", err)
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	identity, err := identityclient.New(identityclient.Options{
		Address:      cfg.Identity.Address,
		ServiceToken: cfg.Identity.ServiceToken,
		CAFile:       cfg.Identity.CAFile,
		ServerName:   cfg.Identity.ServerName,
		Timeout:      cfg.Identity.Timeout,
	})
	if err != nil {
		return fmt.Errorf("initialize Identity client: %w", err)
	}
	defer func() { _ = identity.Close() }()
	application, err := app.New(ctx, cfg, log, identity)
	if err != nil {
		return fmt.Errorf("initialize Content: %w", err)
	}
	if err := application.Run(ctx); err != nil {
		return fmt.Errorf("run Content: %w", err)
	}
	return nil
}
