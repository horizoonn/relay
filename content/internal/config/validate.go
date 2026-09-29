package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"
)

func (c Config) Validate() error {
	if err := c.HTTP.validate(); err != nil {
		return err
	}
	if c.App.ShutdownTimeout <= 0 || c.App.ShutdownTimeout > 2*time.Minute {
		return errors.New("CONTENT_SHUTDOWN_TIMEOUT must be positive and at most 2m")
	}
	if err := c.Postgres.validate(); err != nil {
		return err
	}
	return c.Identity.validate()
}

func (c HTTPConfig) validate() error {
	_, port, err := net.SplitHostPort(c.Address)
	if err != nil {
		return fmt.Errorf("CONTENT_HTTP_ADDR: %w", err)
	}
	if _, parseErr := strconv.ParseUint(port, 10, 16); parseErr != nil {
		return errors.New("CONTENT_HTTP_ADDR must contain a numeric port")
	}
	origin, err := url.Parse(c.AllowedOrigin)
	if err != nil || origin == nil ||
		(origin.Scheme != "http" && origin.Scheme != "https") ||
		origin.Hostname() == "" || origin.User != nil || origin.Path != "" ||
		origin.RawQuery != "" || origin.Fragment != "" || origin.String() != c.AllowedOrigin {
		return errors.New("CONTENT_ALLOWED_ORIGIN must be an HTTP origin")
	}
	if len(c.CursorKey) < 32 {
		return errors.New("CONTENT_CURSOR_SIGNING_KEY must contain at least 32 bytes")
	}
	return nil
}

func (c PostgresConfig) validate() error {
	if c.Host == "" || c.Database == "" || c.User == "" || c.Password == "" {
		return errors.New("content PostgreSQL connection fields must not be empty")
	}
	if c.Port == 0 {
		return errors.New("CONTENT_DB_PORT must be positive")
	}
	switch c.SSLMode {
	case "disable", "allow", "prefer", "require", "verify-ca", "verify-full":
	default:
		return errors.New("CONTENT_DB_SSLMODE is invalid")
	}
	if c.ConnectTimeout <= 0 || c.ConnectTimeout > 30*time.Second {
		return errors.New("CONTENT_DB_CONNECT_TIMEOUT must be positive and at most 30s")
	}
	if c.MaxConns <= 0 || c.MaxConns > 100 ||
		c.MinConns < 0 || c.MinConns > c.MaxConns {
		return errors.New("CONTENT_DB_MIN_CONNS and CONTENT_DB_MAX_CONNS must form a valid range with maximum 100")
	}
	return nil
}

func (c IdentityConfig) validate() error {
	if c.Address == "" || c.ServiceToken == "" {
		return errors.New("CONTENT_IDENTITY_ADDR and CONTENT_IDENTITY_SERVICE_TOKEN must not be empty")
	}
	if _, _, err := net.SplitHostPort(c.Address); err != nil {
		return fmt.Errorf("CONTENT_IDENTITY_ADDR: %w", err)
	}
	if c.Timeout <= 0 || c.Timeout > 10*time.Second {
		return errors.New("CONTENT_IDENTITY_TIMEOUT must be positive and at most 10s")
	}
	return nil
}
