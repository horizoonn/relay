package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	t.Setenv("CONTENT_RATE_LIMIT_KEY", strings.Repeat("r", 32))
	t.Setenv("CONTENT_DB", "relay_content")
	t.Setenv("CONTENT_APP_USER", "content_app")
	t.Setenv("CONTENT_APP_PASSWORD", "local-test-password")
	t.Setenv("CONTENT_ALLOWED_ORIGIN", "https://localhost")
	t.Setenv("CONTENT_CURSOR_SIGNING_KEY", strings.Repeat("k", 32))
	t.Setenv("CONTENT_ACCESS_PUBLIC_KEY_FILES", "test=/run/keys/test.pem")
	t.Setenv("CONTENT_HTTP_ADDR", "127.0.0.1:9080")
	t.Setenv("CONTENT_DB_PORT", "5432")
	t.Setenv("CONTENT_DB_HOST", "postgres")
	t.Setenv("CONTENT_DB_SSLMODE", "disable")
	t.Setenv("CONTENT_DB_MAX_CONNS", "10")
	t.Setenv("CONTENT_DB_MIN_CONNS", "2")
	t.Setenv("CONTENT_DB_CONNECT_TIMEOUT", "5s")
	t.Setenv("CONTENT_SHUTDOWN_TIMEOUT", "30s")

	t.Setenv("CONTENT_LOG_SERVICE_NAME", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Log.ServiceName != "content" {
		t.Fatalf("default service name=%q", cfg.Log.ServiceName)
	}
	t.Run("service name override", func(t *testing.T) {
		t.Setenv("CONTENT_LOG_SERVICE_NAME", "custom-content")
		overridden, loadErr := Load()
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		if overridden.Log.ServiceName != "custom-content" {
			t.Fatalf("service name=%q", overridden.Log.ServiceName)
		}
	})

	if cfg.HTTP.Address != "127.0.0.1:9080" || cfg.Postgres.Database != "relay_content" ||
		cfg.Postgres.User != "content_app" || cfg.Postgres.Port != 5432 ||
		cfg.App.ShutdownTimeout != 30*time.Second {
		t.Fatalf("loaded address=%q database=%q user=%q port=%d shutdown=%s",
			cfg.HTTP.Address, cfg.Postgres.Database, cfg.Postgres.User,
			cfg.Postgres.Port, cfg.App.ShutdownTimeout)
	}
}

func TestLoadRejectsInvalidEnvironment(t *testing.T) {
	t.Setenv("CONTENT_RATE_LIMIT_KEY", strings.Repeat("r", 32))
	t.Setenv("CONTENT_DB", "relay_content")
	t.Setenv("CONTENT_APP_USER", "content_app")
	t.Setenv("CONTENT_APP_PASSWORD", "local-test-password")
	t.Setenv("CONTENT_ALLOWED_ORIGIN", "https://localhost")
	t.Setenv("CONTENT_CURSOR_SIGNING_KEY", strings.Repeat("k", 32))
	t.Setenv("CONTENT_ACCESS_PUBLIC_KEY_FILES", "test=/run/keys/test.pem")
	t.Setenv("CONTENT_DB_PORT", "invalid")
	if _, err := Load(); err == nil {
		t.Fatal("invalid port was accepted")
	}
}

func TestValidateRejectsInvalidSettings(t *testing.T) {
	valid := Config{
		Redis: RedisConfig{
			Address:        "redis:6379",
			Timeout:        200 * time.Millisecond,
			MaxConnections: 10,
		},
		RateLimit: RateLimitConfig{
			Key:     strings.Repeat("r", 32),
			Capture: "30/1m/10",
			Write:   "60/1m/20",
			Read:    "300/1m/60",
			Search:  "60/1m/10",
		},
		App: AppConfig{
			ShutdownTimeout: 30 * time.Second,
		},
		HTTP: HTTPConfig{
			Address:       ":8080",
			AllowedOrigin: "https://localhost",
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
		Access: AccessConfig{
			PublicKeyFiles: map[string]string{"test": "/run/keys/test.pem"},
		},
	}
	for _, tt := range []struct {
		name   string
		change func(*Config)
	}{
		{
			name: "rate key",
			change: func(c *Config) {
				c.RateLimit.Key = "short"
			},
		},
		{
			name: "capture budget",
			change: func(c *Config) {
				c.RateLimit.Capture = "0/1m/10"
			},
		},
		{
			name: "search retention",
			change: func(c *Config) {
				c.RateLimit.Search = "1/24h/2"
			},
		},
		{
			name: "Redis address",
			change: func(c *Config) {
				c.Redis.Address = "missing-port"
			},
		},
		{
			name: "Redis timeout",
			change: func(c *Config) {
				c.Redis.Timeout = 2 * time.Second
			},
		},
		{
			name: "Redis pool",
			change: func(c *Config) {
				c.Redis.MaxConnections = 0
			},
		},
		{
			name: "shutdown timeout",
			change: func(c *Config) {
				c.App.ShutdownTimeout = 0
			},
		},
		{
			name: "excessive shutdown timeout",
			change: func(c *Config) {
				c.App.ShutdownTimeout = 3 * time.Minute
			},
		},
		{
			name: "HTTP address",
			change: func(c *Config) {
				c.HTTP.Address = "invalid"
			},
		},
		{
			name: "HTTP port",
			change: func(c *Config) {
				c.HTTP.Address = ":abc"
			},
		},
		{
			name: "allowed origin",
			change: func(c *Config) {
				c.HTTP.AllowedOrigin = "https://relay.example/path"
			},
		},
		{
			name: "cursor key",
			change: func(c *Config) {
				c.HTTP.CursorKey = "short"
			},
		},
		{
			name: "database port",
			change: func(c *Config) {
				c.Postgres.Port = 0
			},
		},
		{
			name: "database SSL mode",
			change: func(c *Config) {
				c.Postgres.SSLMode = "invalid"
			},
		},
		{
			name: "pool limits",
			change: func(c *Config) {
				c.Postgres.MinConns = 11
			},
		},
		{
			name: "excessive pool",
			change: func(c *Config) {
				c.Postgres.MaxConns = 101
			},
		},
		{
			name: "connect timeout",
			change: func(c *Config) {
				c.Postgres.ConnectTimeout = 0
			},
		},
		{
			name: "excessive connect timeout",
			change: func(c *Config) {
				c.Postgres.ConnectTimeout = time.Minute
			},
		},
		{
			name: "missing access keys",
			change: func(c *Config) {
				c.Access.PublicKeyFiles = nil
			},
		},
		{
			name: "missing key path",
			change: func(c *Config) {
				c.Access.PublicKeyFiles = map[string]string{"test": ""}
			},
		},
		{
			name: "missing key ID",
			change: func(c *Config) {
				c.Access.PublicKeyFiles = map[string]string{"": "/path"}
			},
		},
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
