//go:build integration

package integration

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/content/internal/app"
	"github.com/horizoonn/relay/content/internal/auth"
	"github.com/horizoonn/relay/content/internal/config"
)

type rejectAuth struct{}

func (rejectAuth) Introspect(context.Context, string) (uuid.UUID, error) {
	return uuid.Nil(), auth.ErrUnauthenticated
}

func (rejectAuth) ValidateCSRF(context.Context, string, string) error {
	return auth.ErrUnauthenticated
}

func (rejectAuth) Check(context.Context) error { return nil }

type slowCheckAuth struct {
	rejectAuth
}

func (slowCheckAuth) Check(ctx context.Context) error {
	select {
	case <-time.After(1100 * time.Millisecond):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

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
	cfg := config.Config{
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
		Identity: config.IdentityConfig{
			Address:      "identity:9090",
			ServiceToken: "test-service-token",
			Timeout:      2 * time.Second,
		},
	}
	application, err := app.New(context.Background(), cfg,
		slog.New(slog.NewTextHandler(io.Discard, nil)), slowCheckAuth{})
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
	for {
		if address := application.Address(); address != "" {
			response, err := client.Get("http://" + address + "/readyz")
			if err == nil {
				_ = response.Body.Close()
				if response.StatusCode == http.StatusOK {
					break
				}
				if response.StatusCode != http.StatusServiceUnavailable {
					t.Fatalf("readiness status = %d", response.StatusCode)
				}
			}
		}
		select {
		case err := <-done:
			t.Fatalf("Content stopped before readiness: %v", err)
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("Content did not become ready")
		}
	}
	baseURL := "http://" + application.Address()
	for _, tc := range []struct {
		path string
		want int
	}{
		{"/healthz", http.StatusOK},
		{"/api/v1/items/recent", http.StatusUnauthorized},
	} {
		response, err := client.Get(baseURL + tc.path)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != tc.want {
			t.Fatalf("GET %s status = %d, want %d", tc.path, response.StatusCode, tc.want)
		}
	}
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
