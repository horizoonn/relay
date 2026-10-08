package redis

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

type Config struct {
	Address        string        `env:"REDIS_ADDR" envDefault:"redis:6379"`
	Username       string        `env:"REDIS_USERNAME"`
	Password       string        `env:"REDIS_PASSWORD"`
	Timeout        time.Duration `env:"REDIS_TIMEOUT" envDefault:"200ms"`
	MaxConnections int           `env:"REDIS_MAX_CONNS" envDefault:"10"`
}

func (c Config) Validate() error {
	host, port, err := net.SplitHostPort(c.Address)
	if err != nil || host == "" {
		return errors.New("redis address must contain host and port")
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil ||
		number == 0 ||
		c.Timeout <= 0 ||
		c.Timeout > time.Second ||
		c.MaxConnections < 1 ||
		c.MaxConnections > 100 {
		return errors.New("invalid Redis address, timeout or connection limit")
	}
	return nil
}

func NewClient(cfg Config) (*redis.Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate Redis config: %w", err)
	}
	return redis.NewClient(&redis.Options{
		Addr:                  cfg.Address,
		Username:              cfg.Username,
		Password:              cfg.Password,
		DialTimeout:           cfg.Timeout,
		ReadTimeout:           cfg.Timeout,
		WriteTimeout:          cfg.Timeout,
		PoolTimeout:           cfg.Timeout,
		ContextTimeoutEnabled: true,
		MaxRetries:            3,
		DialerRetries:         5,
		PoolSize:              cfg.MaxConnections,
		MaxActiveConns:        cfg.MaxConnections,
		ConnMaxIdleTime:       5 * time.Minute,
	}), nil
}
