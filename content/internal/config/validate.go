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
		return fmt.Errorf("validate HTTP config: %w", err)
	}
	if c.App.ShutdownTimeout <= 0 || c.App.ShutdownTimeout > 2*time.Minute {
		return errors.New("CONTENT_SHUTDOWN_TIMEOUT must be positive and at most 2m")
	}
	if err := c.Postgres.Validate(); err != nil {
		return fmt.Errorf("validate PostgreSQL config: %w", err)
	}
	if err := c.Redis.Validate(); err != nil {
		return fmt.Errorf("validate Redis config: %w", err)
	}
	if _, err := c.RateLimit.Rules(); err != nil {
		return fmt.Errorf("validate rate limit config: %w", err)
	}
	if err := c.Access.validate(); err != nil {
		return fmt.Errorf("validate access verification config: %w", err)
	}
	return nil
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
		origin.Scheme != "https" ||
		origin.Hostname() == "" || origin.User != nil || origin.Path != "" ||
		origin.RawQuery != "" || origin.ForceQuery || origin.Fragment != "" ||
		origin.Opaque != "" || origin.String() != c.AllowedOrigin {
		return errors.New("CONTENT_ALLOWED_ORIGIN must be an HTTPS origin")
	}
	if len(c.CursorKey) < 32 {
		return errors.New("CONTENT_CURSOR_SIGNING_KEY must contain at least 32 bytes")
	}
	return nil
}

func (c AccessConfig) validate() error {
	if len(c.PublicKeyFiles) == 0 || len(c.PublicKeyFiles) > 8 {
		return errors.New("CONTENT_ACCESS_PUBLIC_KEY_FILES requires one to eight public keys")
	}
	for id, path := range c.PublicKeyFiles {
		if id == "" || len(id) > 64 || path == "" {
			return errors.New("access public keys require key IDs and file paths")
		}
	}
	return nil
}
