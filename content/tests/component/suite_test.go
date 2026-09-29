//go:build component

package component

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
	"uuid"

	platformpostgres "github.com/horizoonn/relay/platform/pkg/postgres"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/horizoonn/relay/content/internal/auth"
	contentrepo "github.com/horizoonn/relay/content/internal/repository/postgres"
	contenthttp "github.com/horizoonn/relay/content/internal/transport/http/contentv1"
	"github.com/horizoonn/relay/content/internal/usecase/capture"
	"github.com/horizoonn/relay/content/internal/usecase/collection"
	"github.com/horizoonn/relay/content/internal/usecase/item"
	"github.com/horizoonn/relay/content/internal/usecase/search"
)

const origin = "https://relay.example"

type authenticator struct {
	owner uuid.UUID
}

func (a authenticator) Introspect(
	_ context.Context,
	token string,
) (uuid.UUID, error) {
	if token != "access" {
		return uuid.Nil(), auth.ErrUnauthenticated
	}
	return a.owner, nil
}

func (a authenticator) ValidateCSRF(
	_ context.Context,
	token, csrf string,
) error {
	if token != "access" || csrf != "csrf" {
		return auth.ErrForbidden
	}
	return nil
}

type fixture struct {
	t       *testing.T
	ctx     context.Context
	pool    *pgxpool.Pool
	owner   uuid.UUID
	server  *httptest.Server
	foreign *httptest.Server
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dsn := os.Getenv("RELAY_CONTENT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("RELAY_CONTENT_TEST_DATABASE_URL must point to an isolated migrated Content database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	owner := uuid.New()
	t.Cleanup(func() {
		cleanupCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if _, err := pool.Exec(cleanupCtx, `DELETE FROM content.idempotency_records WHERE owner_id=$1`, owner); err != nil {
			t.Errorf("cleanup receipts: %v", err)
		}
		if _, err := pool.Exec(cleanupCtx, `DELETE FROM content.items WHERE owner_id=$1`, owner); err != nil {
			t.Errorf("cleanup items: %v", err)
		}
	})
	tx := platformpostgres.NewTxManager(pool)
	repo := contentrepo.NewRepository(tx.Executor, 5*time.Second)
	codec, err := contenthttp.NewCursorCodec([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := contenthttp.NewHandler(capture.NewService(repo, repo, tx),
		item.NewService(repo, tx), collection.NewService(repo), search.NewService(repo), codec,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	serve := func(user uuid.UUID) *httptest.Server {
		t.Helper()
		httpHandler, err := contenthttp.NewServer(handler, authenticator{
			owner: user,
		}, origin)
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewServer(httpHandler)
		t.Cleanup(server.Close)
		return server
	}
	return &fixture{
		t:       t,
		ctx:     ctx,
		pool:    pool,
		owner:   owner,
		server:  serve(owner),
		foreign: serve(uuid.New()),
	}
}

func (f *fixture) call(
	server *httptest.Server,
	method, path, body, mediaType, key string,
) (int, http.Header, []byte) {
	f.t.Helper()
	req, err := http.NewRequestWithContext(f.ctx, method, server.URL+path, strings.NewReader(body))
	if err != nil {
		f.t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{
		Name:  "relay_access_token",
		Value: "access",
	})
	if mediaType != "" {
		req.Header.Set("Content-Type", mediaType)
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	if method != http.MethodGet {
		req.Header.Set("Origin", origin)
		req.Header.Set("X-CSRF-Token", "csrf")
	}
	response, err := server.Client().Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		f.t.Fatal(err)
	}
	return response.StatusCode, response.Header, data
}
