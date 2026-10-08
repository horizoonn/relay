//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/platform/pkg/security/accessjwt"
	"go.uber.org/zap"

	"github.com/horizoonn/relay/content/internal/app"
	"github.com/horizoonn/relay/content/internal/config"
)

func TestAppStartupAndProbes(t *testing.T) {
	if os.Getenv("RELAY_CONTENT_TEST_DATABASE_URL") == "" {
		t.Fatal("RELAY_CONTENT_TEST_DATABASE_URL must point to an isolated migrated Content database")
	}
	if os.Getenv("PGHOST") == "" || os.Getenv("PGPORT") == "" ||
		os.Getenv("PGUSER") == "" || os.Getenv("PGPASSWORD") == "" ||
		os.Getenv("PGDATABASE") == "" {
		t.Skip("app startup test needs PGHOST, PGPORT, PGUSER, PGPASSWORD and PGDATABASE; task test:db provides them")
	}
	port, err := strconv.ParseUint(os.Getenv("PGPORT"), 10, 16)
	if err != nil || port == 0 {
		t.Fatal("PGPORT must be a valid PostgreSQL port")
	}

	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "public.pem")
	if writeErr := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	cfg := config.Config{
		Redis: config.RedisConfig{
			Address:        "127.0.0.1:1",
			Timeout:        100 * time.Millisecond,
			MaxConnections: 2,
		},
		RateLimit: config.RateLimitConfig{
			Key:     strings.Repeat("r", 32),
			Capture: "30/1m/10",
			Write:   "60/1m/20",
			Read:    "300/1m/60",
			Search:  "60/1m/10",
		},
		App: config.AppConfig{
			ShutdownTimeout: time.Second,
		},
		HTTP: config.HTTPConfig{
			Address:       "127.0.0.1:0",
			AllowedOrigin: "https://relay.example",
			CursorKey:     strings.Repeat("x", 32),
		},
		Postgres: config.PostgresConfig{
			Host:           os.Getenv("PGHOST"),
			Port:           uint16(port),
			Database:       os.Getenv("PGDATABASE"),
			User:           os.Getenv("PGUSER"),
			Password:       os.Getenv("PGPASSWORD"),
			SSLMode:        "disable",
			MaxConns:       2,
			MinConns:       0,
			ConnectTimeout: time.Second,
		},
		Access: config.AccessConfig{
			PublicKeyFiles: map[string]string{"integration": keyFile},
		},
	}
	application, err := app.New(context.Background(), cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- application.Run(ctx) }()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	client := &http.Client{
		Timeout: 3 * time.Second,
	}
	defer client.CloseIdleConnections()
	for {
		if address := application.HTTPAddress(); address != "" {
			request, requestErr := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+address+"/readyz", nil)
			if requestErr != nil {
				t.Fatal(requestErr)
			}
			response, callErr := client.Do(request)
			if callErr == nil {
				_, readErr := io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
				if readErr != nil {
					t.Fatal(readErr)
				}
				if response.StatusCode == http.StatusOK {
					break
				}
				if response.StatusCode != http.StatusServiceUnavailable {
					t.Fatalf("readiness status = %d", response.StatusCode)
				}
			}
		}
		select {
		case runErr := <-done:
			t.Fatalf("Content stopped before readiness: %v", runErr)
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("Content did not become ready")
		}
	}
	issuer, err := accessjwt.NewIssuer("integration", private)
	if err != nil {
		t.Fatal(err)
	}
	token, err := issuer.Issue(uuid.NewV7(), uuid.NewV7(), [32]byte{1}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	baseURL := "http://" + application.HTTPAddress()
	for _, tc := range []struct {
		path   string
		want   int
		access bool
	}{
		{
			path:   "/healthz",
			want:   http.StatusOK,
			access: false,
		},
		{
			path:   "/readyz",
			want:   http.StatusOK,
			access: false,
		},
		{
			path:   "/api/v1/items/recent",
			want:   http.StatusUnauthorized,
			access: false,
		},
		{
			path:   "/api/v1/items/recent",
			want:   http.StatusOK,
			access: true,
		},
	} {
		request, requestErr := http.NewRequestWithContext(t.Context(), http.MethodGet, baseURL+tc.path, nil)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		if tc.access {
			request.AddCookie(&http.Cookie{
				Name:  "__Host-relay_access",
				Value: token.Raw,
			})
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, readErr := io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if response.StatusCode != tc.want {
			t.Fatalf("GET %s status = %d, want %d", tc.path, response.StatusCode, tc.want)
		}
	}
	client.CloseIdleConnections()
	cancel()
	shutdownDeadline := time.NewTimer(5 * time.Second)
	defer shutdownDeadline.Stop()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-shutdownDeadline.C:
		t.Fatal("Content did not stop")
	}
}
