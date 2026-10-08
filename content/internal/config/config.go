package config

import (
	"fmt"
	"time"

	"github.com/caarlos0/env/v11"
	platformpostgres "github.com/horizoonn/relay/platform/pkg/postgres"
)

type Config struct {
	App      AppConfig
	HTTP     HTTPConfig
	Postgres PostgresConfig
	Identity IdentityConfig
}

type AppConfig struct {
	ShutdownTimeout time.Duration `env:"SHUTDOWN_TIMEOUT" envDefault:"30s"`
}

type HTTPConfig struct {
	Address       string `env:"HTTP_ADDR" envDefault:":8080"`
	AllowedOrigin string `env:"ALLOWED_ORIGIN,required,notEmpty"`
	CursorKey     string `env:"CURSOR_SIGNING_KEY,required,notEmpty"`
}

type PostgresConfig = platformpostgres.Config

type IdentityConfig struct {
	Address      string        `env:"IDENTITY_ADDR,required,notEmpty"`
	ServiceToken string        `env:"IDENTITY_SERVICE_TOKEN,required,notEmpty"`
	CAFile       string        `env:"IDENTITY_CA_FILE"`
	ServerName   string        `env:"IDENTITY_SERVER_NAME"`
	Timeout      time.Duration `env:"IDENTITY_TIMEOUT" envDefault:"2s"`
}

func Load() (Config, error) {
	cfg, err := env.ParseAsWithOptions[Config](env.Options{
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
