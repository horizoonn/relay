//go:build component

package component

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/platform/pkg/postgres"
	"github.com/horizoonn/relay/platform/pkg/ratelimit"
	"github.com/horizoonn/relay/platform/pkg/security/accessjwt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	contentlimit "github.com/horizoonn/relay/content/internal/ratelimit"
	contentrepo "github.com/horizoonn/relay/content/internal/repository/postgres"
	contenthttp "github.com/horizoonn/relay/content/internal/transport/http/contentv1"
	"github.com/horizoonn/relay/content/internal/usecase/capture"
	"github.com/horizoonn/relay/content/internal/usecase/collection"
	"github.com/horizoonn/relay/content/internal/usecase/item"
	"github.com/horizoonn/relay/content/internal/usecase/search"
)

const origin = "https://relay.example"

type fixture struct {
	ctx     context.Context //nolint:containedctx // One bounded context covers HTTP and database operations.
	pool    *pgxpool.Pool
	owner   uuid.UUID
	server  *httptest.Server
	foreign *httptest.Server
	replica *httptest.Server
	redis   *redis.Client
	tokens  map[*httptest.Server]string
	csrf    string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return newFixtureWithRules(t, nil)
}

func newFixtureWithRules(t *testing.T, overrides map[contentlimit.Scope]ratelimit.Rule) *fixture {
	t.Helper()
	value := os.Getenv("RELAY_CONTENT_TEST_REDIS_URL")
	if value == "" {
		t.Fatal("RELAY_CONTENT_TEST_REDIS_URL must point to isolated Redis")
	}
	options, err := redis.ParseURL(value)
	if err != nil {
		t.Fatal(err)
	}
	options.MaxRetries = -1
	options.DialerRetries = 1
	options.ContextTimeoutEnabled = true
	client := redis.NewClient(options)
	t.Cleanup(func() { _ = client.Close() })
	if err = client.Ping(t.Context()).Err(); err != nil {
		t.Fatal(err)
	}
	rules := make(map[contentlimit.Scope]ratelimit.Rule)
	for _, scope := range []contentlimit.Scope{
		contentlimit.Capture,
		contentlimit.Write,
		contentlimit.Read,
		contentlimit.Search,
	} {
		rules[scope] = ratelimit.Rule{
			Rate:   10000,
			Period: time.Second,
			Burst:  10000,
		}
	}
	for scope, rule := range overrides {
		rules[scope] = rule
	}
	limiter, err := contentlimit.NewLimiter(client, []byte(uuid.NewV7().String()), time.Second, rules, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	dsn := os.Getenv("RELAY_CONTENT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("RELAY_CONTENT_TEST_DATABASE_URL must point to an isolated migrated Content database")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if pingErr := pool.Ping(ctx); pingErr != nil {
		t.Fatal(pingErr)
	}
	owner := uuid.New()
	t.Cleanup(func() {
		cleanupCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if _, cleanupErr := pool.Exec(
			cleanupCtx,
			`DELETE FROM content.idempotency_records WHERE owner_id=$1`,
			owner,
		); cleanupErr != nil {
			t.Errorf("cleanup receipts: %v", cleanupErr)
		}
		if _, cleanupErr := pool.Exec(cleanupCtx, `DELETE FROM content.items WHERE owner_id=$1`, owner); cleanupErr != nil {
			t.Errorf("cleanup items: %v", cleanupErr)
		}
	})
	tx := postgres.NewTxManager(pool)
	repo := contentrepo.NewRepository(tx.Executor, 5*time.Second)
	codec, err := contenthttp.NewCursorCodec([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := contenthttp.NewHandler(capture.NewService(repo, repo, tx),
		item.NewService(repo, tx), collection.NewService(repo), search.NewService(repo), codec,
		zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := accessjwt.NewIssuer("component", private)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := accessjwt.NewVerifier(map[string]ed25519.PublicKey{"component": public})
	if err != nil {
		t.Fatal(err)
	}
	rawCSRF := make([]byte, 32)
	if _, err := rand.Read(rawCSRF); err != nil {
		t.Fatal(err)
	}
	csrf := base64.RawURLEncoding.EncodeToString(rawCSRF)
	tokens := make(map[*httptest.Server]string)
	serve := func(user uuid.UUID) *httptest.Server {
		t.Helper()
		httpHandler, err := contenthttp.NewServer(handler, verifier, origin, limiter)
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewServer(httpHandler)
		t.Cleanup(server.Close)
		token, err := issuer.Issue(user, uuid.NewV7(), sha256.Sum256([]byte(csrf)), time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		tokens[server] = token.Raw
		return server
	}
	return &fixture{
		ctx:     ctx,
		pool:    pool,
		owner:   owner,
		server:  serve(owner),
		foreign: serve(uuid.New()),
		replica: serve(owner),
		redis:   client,
		tokens:  tokens,
		csrf:    csrf,
	}
}

func (f *fixture) call(
	t *testing.T,
	server *httptest.Server,
	method, path, body, mediaType, key string,
) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(f.ctx, method, server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{
		Name:  "__Host-relay_access",
		Value: f.tokens[server],
	})
	if mediaType != "" {
		req.Header.Set("Content-Type", mediaType)
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	if method != http.MethodGet {
		req.Header.Set("Origin", origin)
		req.Header.Set("X-CSRF-Token", f.csrf)
		req.AddCookie(&http.Cookie{
			Name:  "__Host-relay_csrf",
			Value: f.csrf,
		})
	}
	response, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, response.Header, data
}
