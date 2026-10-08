package config

import (
	"fmt"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/horizoonn/relay/platform/pkg/logger"
	"github.com/horizoonn/relay/platform/pkg/postgres"
)

type Config struct {
	Log       logger.Config
	App       AppConfig
	HTTP      HTTPConfig
	Postgres  PostgresConfig
	Access    AccessConfig
	Redis     RedisConfig
	RateLimit RateLimitConfig
}

type AppConfig struct {
	ShutdownTimeout time.Duration `env:"SHUTDOWN_TIMEOUT" envDefault:"30s"`
}

type HTTPConfig struct {
	Address       string `env:"HTTP_ADDR" envDefault:":8080"`
	AllowedOrigin string `env:"ALLOWED_ORIGIN,required,notEmpty"`
	CursorKey     string `env:"CURSOR_SIGNING_KEY,required,notEmpty"`
}

type PostgresConfig = postgres.Config

type AccessConfig struct {
	PublicKeyFiles map[string]string `env:"ACCESS_PUBLIC_KEY_FILES,required,notEmpty" envSeparator:"," envKeyValSeparator:"="`
}

func Load() (Config, error) {
	cfg := Config{
		Log: logger.Config{
			ServiceName: "content",
		},
	}
	err := env.ParseWithOptions(&cfg, env.Options{
		Prefix: "CONTENT_",
	})
	if err != nil {
		return Config{}, fmt.Errorf("parse Content environment: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("validate Content config: %w", err)
	}
	return cfg, nil
}
