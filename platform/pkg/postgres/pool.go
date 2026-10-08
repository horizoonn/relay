package postgres

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Config struct {
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

func (c Config) Validate() error {
	if c.Host == "" || c.Database == "" || c.User == "" || c.Password == "" || c.Port == 0 {
		return errors.New("PostgreSQL connection fields must not be empty")
	}
	switch c.SSLMode {
	case "disable", "allow", "prefer", "require", "verify-ca", "verify-full":
	default:
		return errors.New("invalid PostgreSQL SSL mode")
	}
	if c.ConnectTimeout <= 0 ||
		c.ConnectTimeout > 30*time.Second ||
		c.MaxConns <= 0 ||
		c.MaxConns > 100 ||
		c.MinConns < 0 ||
		c.MinConns > c.MaxConns {
		return errors.New("invalid PostgreSQL timeout or connection limits")
	}
	return nil
}

func NewPool(ctx context.Context, cfg Config) (*pgxpool.Pool, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate PostgreSQL config: %w", err)
	}
	uri := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(cfg.User, cfg.Password),
		Host:   net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port))),
		Path:   "/" + cfg.Database,
	}
	query := uri.Query()
	query.Set("sslmode", cfg.SSLMode)
	uri.RawQuery = query.Encode()
	settings, err := pgxpool.ParseConfig(uri.String())
	if err != nil {
		return nil, errors.New("invalid PostgreSQL connection settings")
	}
	settings.MaxConns = cfg.MaxConns
	settings.MinConns = cfg.MinConns
	settings.ConnConfig.ConnectTimeout = cfg.ConnectTimeout
	pool, err := pgxpool.NewWithConfig(ctx, settings)
	if err != nil {
		return nil, fmt.Errorf("create PostgreSQL pool: %w", err)
	}
	for attempt := 0; attempt < 3; attempt++ {
		pingCtx, cancel := context.WithTimeout(ctx, cfg.ConnectTimeout)
		err = pool.Ping(pingCtx)
		cancel()
		if err == nil {
			return pool, nil
		}
		if attempt < 2 {
			select {
			case <-ctx.Done():
				pool.Close()
				return nil, fmt.Errorf("wait for PostgreSQL startup: %w", ctx.Err())
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
	pool.Close()
	return nil, fmt.Errorf("ping PostgreSQL after three attempts: %w", err)
}
