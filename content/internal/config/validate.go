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
	if err := c.Postgres.Validate(); err != nil {
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
