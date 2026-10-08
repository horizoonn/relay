package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/horizoonn/relay/platform/pkg/logger"

	"github.com/horizoonn/relay/content/internal/app"
	"github.com/horizoonn/relay/content/internal/config"
)

func main() {
	os.Exit(run())
}

func run() (exitCode int) {
	cfg, err := config.Load()
	if err != nil {
		log.Printf("load config: %v", err)
		return 1
	}

	output, err := logger.New(cfg.Log)
	if err != nil {
		log.Printf("initialize logger: %v", err)
		return 1
	}

	defer func() {
		if syncErr := logger.Sync(output); syncErr != nil {
			log.Printf("%v", syncErr)
			exitCode = 1
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	application, err := app.New(ctx, cfg, output)
	if err != nil {
		output.Error("initialize application", logger.ErrorFields(err)...)
		return 1
	}
	if err := application.Run(ctx); err != nil {
		output.Error("run application", logger.ErrorFields(err)...)
		return 1
	}
	return 0
}
