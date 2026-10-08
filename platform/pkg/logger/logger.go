package logger

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"go.uber.org/zap"
)

type Config struct {
	ServiceName string `env:"LOG_SERVICE_NAME"`
	Level       string `env:"LOG_LEVEL" envDefault:"info"`
	Development bool   `env:"LOG_DEVELOPMENT" envDefault:"false"`
}

func New(cfg Config) (*zap.Logger, error) {
	if cfg.ServiceName == "" {
		return nil, errors.New("logger service name is required")
	}
	if cfg.Level == "" {
		cfg.Level = "info"
	}
	level, err := zap.ParseAtomicLevel(cfg.Level)
	if err != nil {
		return nil, errors.New("invalid logger level")
	}
	settings := zap.NewProductionConfig()
	if cfg.Development {
		settings = zap.NewDevelopmentConfig()
	}
	settings.Level = level
	settings.OutputPaths = []string{"stdout"}
	settings.ErrorOutputPaths = []string{"stderr"}
	settings.InitialFields = map[string]any{"service": cfg.ServiceName}

	settings.Sampling = nil
	log, err := settings.Build()
	if err != nil {
		return nil, fmt.Errorf("build logger: %w", err)
	}
	return log, nil
}

func Sync(log *zap.Logger) error {
	err := log.Sync()
	if err == nil || errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTTY) || errors.Is(err, os.ErrInvalid) {
		return nil
	}
	return fmt.Errorf("sync logger: %w", err)
}
