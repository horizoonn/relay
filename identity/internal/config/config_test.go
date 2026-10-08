package config

import (
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	for name, value := range map[string]string{
		"IDENTITY_MAIL_ENCRYPTION_KEY":      "test-mail-encryption-key-at-least-32-bytes",
		"IDENTITY_RATE_LIMIT_KEY":           "local-test-rate-key-at-least-32-bytes",
		"IDENTITY_REDIS_ADDR":               "127.0.0.1:6379",
		"IDENTITY_REDIS_TIMEOUT":            "200ms",
		"IDENTITY_REDIS_MAX_CONNS":          "10",
		"IDENTITY_DB":                       "relay_identity",
		"IDENTITY_APP_USER":                 "identity_app",
		"IDENTITY_APP_PASSWORD":             "local-test-password",
		"IDENTITY_ALLOWED_ORIGIN":           "https://localhost",
		"IDENTITY_SIGNING_KEY_ID":           "local-1",
		"IDENTITY_SIGNING_KEY_FILE":         "/run/secrets/key",
		"IDENTITY_SIGNING_PUBLIC_KEY_FILES": "old=/run/keys/old.pem,older=/run/keys/older.pem",
		"IDENTITY_CURSOR_SIGNING_KEY":       "local-test-cursor-key-32-bytes-long",
		"IDENTITY_HTTP_ADDR":                "127.0.0.1:9080",
		"IDENTITY_MAX_PARALLEL_PASSWORDS":   "2",
		"IDENTITY_SHUTDOWN_TIMEOUT":         "30s",
		"IDENTITY_DB_HOST":                  "postgres",
		"IDENTITY_DB_PORT":                  "5432",
		"IDENTITY_DB_SSLMODE":               "disable",
		"IDENTITY_DB_MAX_CONNS":             "10",
		"IDENTITY_DB_MIN_CONNS":             "2",
		"IDENTITY_DB_CONNECT_TIMEOUT":       "5s",
	} {
		t.Setenv(name, value)
	}
	t.Setenv("IDENTITY_LOG_SERVICE_NAME", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Log.ServiceName != "identity" {
		t.Fatalf("default service name=%q", cfg.Log.ServiceName)
	}
	t.Run("service name override", func(t *testing.T) {
		t.Setenv("IDENTITY_LOG_SERVICE_NAME", "custom-identity")
		overridden, loadErr := Load()
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		if overridden.Log.ServiceName != "custom-identity" {
			t.Fatalf("service name=%q", overridden.Log.ServiceName)
		}
	})

	if cfg.HTTP.Address != "127.0.0.1:9080" || cfg.HTTP.AllowedOrigin != "https://localhost" ||
		cfg.Signing.KeyID != "local-1" || cfg.Signing.KeyFile != "/run/secrets/key" ||
		cfg.Postgres.Database != "relay_identity" || cfg.App.MaxParallelPasswords != 2 ||
		cfg.App.ShutdownTimeout != 30*time.Second {
		t.Fatal("environment was not loaded correctly")
	}
	if len(cfg.Signing.PublicKeyFiles) != 2 || cfg.Signing.PublicKeyFiles["old"] != "/run/keys/old.pem" {
		t.Fatal("previous key file mapping was not loaded")
	}
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{
			name:  "invalid database port",
			key:   "IDENTITY_DB_PORT",
			value: "invalid",
		},
		{
			name:  "missing signing key file",
			key:   "IDENTITY_SIGNING_KEY_FILE",
			value: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(tt.key, tt.value)
			if _, loadErr := Load(); loadErr == nil {
				t.Fatal("invalid environment was accepted")
			}
		})
	}
}

func TestValidate(t *testing.T) {
	valid := Config{
		Mail: MailConfig{
			Address:       "127.0.0.1:1025",
			From:          "no-reply@relay.local",
			Timeout:       time.Second,
			AllowInsecure: true,
			EncryptionKey: "test-mail-encryption-key-at-least-32-bytes",
		},
		Redis: RedisConfig{
			Address:        "redis:6379",
			Timeout:        200 * time.Millisecond,
			MaxConnections: 10,
		},
		RateLimit: RateLimitConfig{
			EmailIP:      "1000/1s/1000",
			EmailAccount: "1000/1s/1000",
			ActionIP:     "1000/1s/1000",
			Key:          "local-test-rate-key-at-least-32-bytes",
			LoginIP:      "30/1m/10",
			LoginAccount: "5/1m/5",
			RegisterIP:   "6/1h/3",
			RefreshIP:    "120/1m/30",
			ReadUser:     "120/1m/30",
			LogoutIP:     "30/1m/10",
			RevokeUser:   "30/1m/10",
		},
		App: AppConfig{
			ShutdownTimeout:      30 * time.Second,
			MaxParallelPasswords: 2,
			EmailWorkers:         2,
		},
		HTTP: HTTPConfig{
			Address:          ":8080",
			AllowedOrigin:    "https://localhost",
			CursorSigningKey: "local-test-cursor-key-32-bytes-long",
		},
		Signing: SigningConfig{
			KeyID:   "local-1",
			KeyFile: "/run/secrets/key",
		},
		Postgres: PostgresConfig{
			Host:           "postgres",
			Port:           5432,
			Database:       "relay_identity",
			User:           "identity_app",
			Password:       "local-test-password",
			SSLMode:        "disable",
			MaxConns:       10,
			MinConns:       2,
			ConnectTimeout: 5 * time.Second,
		},
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*Config)
	}{
		{
			name: "short mail encryption key",
			change: func(c *Config) {
				c.Mail.EncryptionKey = "short"
			},
		},
		{
			name: "SMTP missing port",
			change: func(c *Config) {
				c.Mail.Address = "smtp.example.com"
			},
		},
		{
			name: "SMTP zero port",
			change: func(c *Config) {
				c.Mail.Address = "smtp.example.com:0"
			},
		},
		{
			name: "SMTP sender injection",
			change: func(c *Config) {
				c.Mail.From = "sender@example.com\r\nTo: victim@example.com"
			},
		},
		{
			name: "SMTP zero timeout",
			change: func(c *Config) {
				c.Mail.Timeout = 0
			},
		},
		{
			name: "SMTP excessive timeout",
			change: func(c *Config) {
				c.Mail.Timeout = 11 * time.Second
			},
		},
		{
			name: "SMTP partial credentials",
			change: func(c *Config) {
				c.Mail.Username = "user"
			},
		},
		{
			name: "SMTP credentials without TLS",
			change: func(c *Config) {
				c.Mail.Username = "user"
				c.Mail.Password = "secret"
				c.Mail.AllowInsecure = true
			},
		},
		{
			name: "invalid rate rule",
			change: func(c *Config) {
				c.RateLimit.LoginIP = "0/1m/1"
			},
		},
		{
			name: "short rate key",
			change: func(c *Config) {
				c.RateLimit.Key = "short"
			},
		},
		{
			name: "global trusted proxy",
			change: func(c *Config) {
				c.HTTP.TrustedProxyPrefixes = []string{"0.0.0.0/0"}
			},
		},
		{
			name: "invalid trusted proxy",
			change: func(c *Config) {
				c.HTTP.TrustedProxyPrefixes = []string{"invalid"}
			},
		},
		{
			name: "Redis port",
			change: func(c *Config) {
				c.Redis.Address = "redis:0"
			},
		},
		{
			name: "Redis timeout",
			change: func(c *Config) {
				c.Redis.Timeout = 0
			},
		},
		{
			name: "Redis connections",
			change: func(c *Config) {
				c.Redis.MaxConnections = 0
			},
		},
		{
			name: "short cursor key",
			change: func(c *Config) {
				c.HTTP.CursorSigningKey = "short"
			},
		},
		{
			name: "HTTP origin",
			change: func(c *Config) {
				c.HTTP.AllowedOrigin = "http://localhost"
			},
		},
		{
			name: "origin path",
			change: func(c *Config) {
				c.HTTP.AllowedOrigin = "https://localhost/"
			},
		},
		{
			name: "origin query",
			change: func(c *Config) {
				c.HTTP.AllowedOrigin = "https://localhost?"
			},
		},
		{
			name: "origin userinfo",
			change: func(c *Config) {
				c.HTTP.AllowedOrigin = "https://user@localhost"
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
			name: "key file",
			change: func(c *Config) {
				c.Signing.KeyFile = ""
			},
		},
		{
			name: "key ID",
			change: func(c *Config) {
				c.Signing.KeyID = ""
			},
		},
		{
			name: "key ID control",
			change: func(c *Config) {
				c.Signing.KeyID = "key\n"
			},
		},
		{
			name: "previous key override",
			change: func(c *Config) {
				c.Signing.PublicKeyFiles = map[string]string{"local-1": "/keys/key.pem"}
			},
		},
		{
			name: "previous empty path",
			change: func(c *Config) {
				c.Signing.PublicKeyFiles = map[string]string{"old": ""}
			},
		},
		{
			name: "previous empty ID",
			change: func(c *Config) {
				c.Signing.PublicKeyFiles = map[string]string{"": "/keys/key.pem"}
			},
		},
		{
			name: "zero email workers",
			change: func(c *Config) {
				c.App.EmailWorkers = 0
			},
		},
		{
			name: "excessive email workers",
			change: func(c *Config) {
				c.App.EmailWorkers = 5
			},
		},
		{
			name: "password slots",
			change: func(c *Config) {
				c.App.MaxParallelPasswords = 0
			},
		},
		{
			name: "excessive slots",
			change: func(c *Config) {
				c.App.MaxParallelPasswords = 17
			},
		},
		{
			name: "shutdown",
			change: func(c *Config) {
				c.App.ShutdownTimeout = 0
			},
		},
		{
			name: "excessive shutdown",
			change: func(c *Config) {
				c.App.ShutdownTimeout = 3 * time.Minute
			},
		},
		{
			name: "database password",
			change: func(c *Config) {
				c.Postgres.Password = ""
			},
		},
		{
			name: "database port",
			change: func(c *Config) {
				c.Postgres.Port = 0
			},
		},
		{
			name: "SSL mode",
			change: func(c *Config) {
				c.Postgres.SSLMode = "invalid"
			},
		},
		{
			name: "pool range",
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid
			tc.change(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}
