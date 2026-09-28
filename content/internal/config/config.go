package config

import (
	"fmt"
	"time"

	"github.com/caarlos0/env/v11"
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

type PostgresConfig struct {
	Host           string        `env:"DB_HOST" envDefault:"postgres"`
	Port           uint16        `env:"DB_PORT" envDefault:"5432"`
	Database       string        `env:"DB,required,notEmpty"`
	User           string        `env:"APP_USER,required,notEmpty"`
	Password       string        `env:"APP_PASSWORD,required,notEmpty"`
	SSLMode        string        `env:"DB_SSLMODE" envDefault:"disable"`
	MaxConns       int32         `env:"DB_MAX_CONNS" envDefault:"10"`
	MinConns       int32         `env:"DB_MIN_CONNS" envDefault:"2"`
	ConnectTimeout time.Duration `env:"DB_CONNECT_TIMEOUT" envDefault:"5s"`
}

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
