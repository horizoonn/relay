package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	t.Setenv("CONTENT_DB", "relay_content")
	t.Setenv("CONTENT_APP_USER", "content_app")
	t.Setenv("CONTENT_APP_PASSWORD", "local-test-password")
	t.Setenv("CONTENT_ALLOWED_ORIGIN", "http://localhost:8080")
	t.Setenv("CONTENT_CURSOR_SIGNING_KEY", strings.Repeat("k", 32))
	t.Setenv("CONTENT_HTTP_ADDR", "127.0.0.1:9080")
	t.Setenv("CONTENT_DB_PORT", "5432")
	t.Setenv("CONTENT_DB_HOST", "postgres")
	t.Setenv("CONTENT_DB_SSLMODE", "disable")
	t.Setenv("CONTENT_DB_MAX_CONNS", "10")
	t.Setenv("CONTENT_DB_MIN_CONNS", "2")
	t.Setenv("CONTENT_DB_CONNECT_TIMEOUT", "5s")
	t.Setenv("CONTENT_SHUTDOWN_TIMEOUT", "30s")
	t.Setenv("CONTENT_IDENTITY_ADDR", "identity:9090")
	t.Setenv("CONTENT_IDENTITY_SERVICE_TOKEN", "test-service-token")
	t.Setenv("CONTENT_IDENTITY_CA_FILE", "")
	t.Setenv("CONTENT_IDENTITY_SERVER_NAME", "identity")
	t.Setenv("CONTENT_IDENTITY_TIMEOUT", "2s")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTP.Address != "127.0.0.1:9080" || cfg.Postgres.Database != "relay_content" ||
		cfg.Postgres.User != "content_app" || cfg.Postgres.Port != 5432 ||
		cfg.App.ShutdownTimeout != 30*time.Second {
		t.Fatalf("loaded address=%q database=%q user=%q port=%d shutdown=%s",
			cfg.HTTP.Address, cfg.Postgres.Database, cfg.Postgres.User,
			cfg.Postgres.Port, cfg.App.ShutdownTimeout)
	}
}

func TestLoadRejectsInvalidEnvironment(t *testing.T) {
	t.Setenv("CONTENT_DB", "relay_content")
	t.Setenv("CONTENT_APP_USER", "content_app")
	t.Setenv("CONTENT_APP_PASSWORD", "local-test-password")
	t.Setenv("CONTENT_ALLOWED_ORIGIN", "http://localhost:8080")
	t.Setenv("CONTENT_CURSOR_SIGNING_KEY", strings.Repeat("k", 32))
	t.Setenv("CONTENT_IDENTITY_ADDR", "identity:9090")
	t.Setenv("CONTENT_IDENTITY_SERVICE_TOKEN", "test-service-token")
	t.Setenv("CONTENT_DB_PORT", "invalid")
	if _, err := Load(); err == nil {
		t.Fatal("invalid port was accepted")
	}
}

func TestValidateRejectsInvalidSettings(t *testing.T) {
	valid := Config{
		App: AppConfig{
			ShutdownTimeout: 30 * time.Second,
		},
		HTTP: HTTPConfig{
			Address:       ":8080",
			AllowedOrigin: "http://localhost:8080",
			CursorKey:     strings.Repeat("k", 32),
		},
		Postgres: PostgresConfig{
			Host:           "postgres",
			Port:           5432,
			Database:       "relay_content",
			User:           "content_app",
			Password:       "local-test-password",
			SSLMode:        "disable",
			MaxConns:       10,
			MinConns:       2,
			ConnectTimeout: 5 * time.Second,
		},
		Identity: IdentityConfig{
			Address:      "identity:9090",
			ServiceToken: "test-service-token",
			Timeout:      2 * time.Second,
		},
	}
	for _, tt := range []struct {
		name   string
		change func(*Config)
	}{
		{"shutdown timeout", func(c *Config) { c.App.ShutdownTimeout = 0 }},
		{"excessive shutdown timeout", func(c *Config) { c.App.ShutdownTimeout = 3 * time.Minute }},
		{"HTTP address", func(c *Config) { c.HTTP.Address = "invalid" }},
		{"HTTP port", func(c *Config) { c.HTTP.Address = ":abc" }},
		{"allowed origin", func(c *Config) { c.HTTP.AllowedOrigin = "https://relay.example/path" }},
		{"cursor key", func(c *Config) { c.HTTP.CursorKey = "short" }},
		{"database port", func(c *Config) { c.Postgres.Port = 0 }},
		{"database SSL mode", func(c *Config) { c.Postgres.SSLMode = "invalid" }},
		{"pool limits", func(c *Config) { c.Postgres.MinConns = 11 }},
		{"excessive pool", func(c *Config) { c.Postgres.MaxConns = 101 }},
		{"connect timeout", func(c *Config) { c.Postgres.ConnectTimeout = 0 }},
		{"excessive connect timeout", func(c *Config) { c.Postgres.ConnectTimeout = time.Minute }},
		{"Identity address", func(c *Config) { c.Identity.Address = "invalid" }},
		{"Identity service token", func(c *Config) { c.Identity.ServiceToken = "" }},
		{"Identity timeout", func(c *Config) { c.Identity.Timeout = 0 }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid
			tt.change(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("invalid config was accepted")
			}
		})
	}
}
