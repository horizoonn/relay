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
	Signing   SigningConfig
	Redis     RedisConfig
	RateLimit RateLimitConfig
	Mail      MailConfig
}

type AppConfig struct {
	ShutdownTimeout      time.Duration `env:"SHUTDOWN_TIMEOUT" envDefault:"30s"`
	MaxParallelPasswords int           `env:"MAX_PARALLEL_PASSWORDS" envDefault:"2"`
	EmailWorkers         int           `env:"EMAIL_WORKERS" envDefault:"2"`
}

type HTTPConfig struct {
	TrustedProxyPrefixes []string `env:"TRUSTED_PROXY_PREFIXES" envSeparator:","`
	Address              string   `env:"HTTP_ADDR" envDefault:":8080"`
	CursorSigningKey     string   `env:"CURSOR_SIGNING_KEY,required,notEmpty"`
	AllowedOrigin        string   `env:"ALLOWED_ORIGIN,required,notEmpty"`
}

type PostgresConfig = postgres.Config

type SigningConfig struct {
	KeyID          string            `env:"SIGNING_KEY_ID,required,notEmpty"`
	KeyFile        string            `env:"SIGNING_KEY_FILE,required,notEmpty"`
	PublicKeyFiles map[string]string `env:"SIGNING_PUBLIC_KEY_FILES" envSeparator:"," envKeyValSeparator:"="`
}

func Load() (Config, error) {
	cfg := Config{
		Log: logger.Config{
			ServiceName: "identity",
		},
	}
	err := env.ParseWithOptions(&cfg, env.Options{
		Prefix: "IDENTITY_",
	})
	if err != nil {
		return Config{}, fmt.Errorf("parse Identity environment: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("validate Identity config: %w", err)
	}
	return cfg, nil
}
