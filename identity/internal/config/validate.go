package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (c Config) Validate() error {
	if err := c.HTTP.validate(); err != nil {
		return fmt.Errorf("validate HTTP config: %w", err)
	}
	if c.App.ShutdownTimeout <= 0 || c.App.ShutdownTimeout > 2*time.Minute {
		return errors.New("IDENTITY_SHUTDOWN_TIMEOUT must be positive and at most 2m")
	}
	if c.App.MaxParallelPasswords <= 0 || c.App.MaxParallelPasswords > 16 {
		return errors.New("IDENTITY_MAX_PARALLEL_PASSWORDS must be between 1 and 16")
	}
	if c.App.EmailWorkers < 1 || c.App.EmailWorkers > 4 {
		return errors.New("IDENTITY_EMAIL_WORKERS must be between 1 and 4")
	}
	if err := c.Signing.validate(); err != nil {
		return fmt.Errorf("validate access signing config: %w", err)
	}
	if err := c.Redis.Validate(); err != nil {
		return fmt.Errorf("validate Redis config: %w", err)
	}
	if _, err := c.RateLimit.Rules(); err != nil {
		return fmt.Errorf("validate rate limit config: %w", err)
	}
	if err := c.Mail.validate(); err != nil {
		return fmt.Errorf("validate mail config: %w", err)
	}
	if err := c.Postgres.Validate(); err != nil {
		return fmt.Errorf("validate PostgreSQL config: %w", err)
	}
	return nil
}

func (c SigningConfig) validate() error {
	if c.KeyFile == "" || c.KeyID == "" || len(c.KeyID) > 64 ||
		strings.ContainsAny(c.KeyID, "\r\n\x00") {
		return errors.New("identity signing key file and a valid key ID are required")
	}
	if len(c.PublicKeyFiles) > 7 {
		return errors.New("at most seven previous public keys may be configured")
	}
	for keyID, path := range c.PublicKeyFiles {
		if keyID == "" || keyID == c.KeyID || path == "" {
			return errors.New("previous public keys require distinct key IDs and file paths")
		}
	}
	return nil
}

func (c HTTPConfig) validate() error {
	if err := validateTrustedProxyPrefixes(c.TrustedProxyPrefixes); err != nil {
		return err
	}
	if len(c.CursorSigningKey) < 32 {
		return errors.New("IDENTITY_CURSOR_SIGNING_KEY must contain at least 32 bytes")
	}
	_, port, err := net.SplitHostPort(c.Address)
	if err != nil {
		return errors.New("IDENTITY_HTTP_ADDR must contain a host and numeric port")
	}
	if _, parseErr := strconv.ParseUint(port, 10, 16); parseErr != nil {
		return errors.New("IDENTITY_HTTP_ADDR must contain a numeric port")
	}
	return validateHTTPSOrigin(c.AllowedOrigin)
}

func validateHTTPSOrigin(value string) error {
	origin, err := url.Parse(value)
	if err != nil || origin == nil || origin.Scheme != "https" || origin.Hostname() == "" ||
		origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.ForceQuery ||
		origin.Fragment != "" || origin.Opaque != "" || origin.String() != value {
		return errors.New("IDENTITY_ALLOWED_ORIGIN must be an HTTPS origin")
	}
	return nil
}

func validateTrustedProxyPrefixes(values []string) error {
	for _, raw := range values {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix != prefix.Masked() || prefix.Bits() == 0 {
			return errors.New("trusted proxy prefixes must be canonical non-global CIDRs")
		}
	}

	return nil
}
