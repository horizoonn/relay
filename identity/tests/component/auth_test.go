//go:build component

package component

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
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

	"github.com/horizoonn/relay/identity/internal/mailcipher"
	"github.com/horizoonn/relay/identity/internal/password"
	identitylimit "github.com/horizoonn/relay/identity/internal/ratelimit"
	tokenrepo "github.com/horizoonn/relay/identity/internal/repository/postgres/accounttoken"
	emailrepo "github.com/horizoonn/relay/identity/internal/repository/postgres/emailjob"
	sessionrepo "github.com/horizoonn/relay/identity/internal/repository/postgres/session"
	userrepo "github.com/horizoonn/relay/identity/internal/repository/postgres/user"
	"github.com/horizoonn/relay/identity/internal/secret"
	identityhttp "github.com/horizoonn/relay/identity/internal/transport/http/identityv1"
	"github.com/horizoonn/relay/identity/internal/usecase/account"
	"github.com/horizoonn/relay/identity/internal/usecase/auth"
	"github.com/horizoonn/relay/identity/internal/usecase/email"
	sessioncase "github.com/horizoonn/relay/identity/internal/usecase/session"
)

type fixture struct {
	pool     *pgxpool.Pool
	server   *httptest.Server
	client   *http.Client
	verifier *accessjwt.Verifier
	issuer   *accessjwt.Issuer
	private  ed25519.PrivateKey
	limiter  *identitylimit.Limiter
	redis    *redis.Client
	accounts *account.Service
	delivery *email.Delivery
	mail     *captureMail
}

type brokenIssuer struct{}

func (brokenIssuer) Issue(uuid.UUID, uuid.UUID, [32]byte, time.Time) (accessjwt.Token, error) {
	return accessjwt.Token{}, errors.New("signing unavailable")
}

func newFixture(t *testing.T, failSigning bool) *fixture {
	t.Helper()
	return newFixtureWithRules(t, failSigning, nil)
}

func newFixtureWithRules(
	t *testing.T,
	failSigning bool,
	overrides map[identitylimit.Scope]ratelimit.Rule,
) *fixture {
	t.Helper()
	dsn := os.Getenv("RELAY_IDENTITY_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("RELAY_IDENTITY_TEST_DATABASE_URL must point to an isolated migrated Identity database")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err = pool.Ping(ctx); err != nil {
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
	var signer auth.AccessIssuer = issuer
	if failSigning {
		signer = brokenIssuer{}
	}
	options, err := redis.ParseURL(os.Getenv("RELAY_IDENTITY_TEST_REDIS_URL"))
	if err != nil {
		t.Fatal("RELAY_IDENTITY_TEST_REDIS_URL must point to isolated Redis")
	}
	options.MaxRetries = -1
	options.DialerRetries = 1
	options.DialTimeout = time.Second
	options.ReadTimeout = time.Second
	options.WriteTimeout = time.Second
	options.ContextTimeoutEnabled = true
	redisConn := redis.NewClient(options)
	t.Cleanup(func() { _ = redisConn.Close() })
	if pingErr := redisConn.Ping(t.Context()).Err(); pingErr != nil {
		t.Fatal(pingErr)
	}
	rules := make(map[identitylimit.Scope]ratelimit.Rule)
	for _, scope := range []identitylimit.Scope{
		identitylimit.LoginIP,
		identitylimit.LoginAccount,
		identitylimit.RegisterIP,
		identitylimit.RefreshIP,
		identitylimit.ReadUser,
		identitylimit.LogoutIP,
		identitylimit.RevokeUser,
		identitylimit.EmailIP,
		identitylimit.EmailAccount,
		identitylimit.ActionIP,
	} {
		// Keep unrelated budgets permissive even when Redis wall time moves backwards.
		rules[scope] = ratelimit.Rule{
			Rate:   10000,
			Period: time.Hour,
			Burst:  10000,
		}
	}
	for scope, rule := range overrides {
		rules[scope] = rule
	}
	limiter, err := identitylimit.NewLimiter(redisConn, []byte(uuid.NewV7().String()), time.Second, rules, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	tx := postgres.NewTxManager(pool)
	jobs := emailrepo.NewRepository(tx.Executor, 5*time.Second)
	cipher, err := mailcipher.New([]byte("component-only-mail-cipher-key-32-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	requests, err := email.NewRequests(jobs, cipher, limiter)
	if err != nil {
		t.Fatal(err)
	}
	tokens := tokenrepo.NewRepository(tx.Executor, 5*time.Second)
	passwords := testPasswordHasher(t)
	service, err := auth.NewService(t.Context(), userrepo.NewRepository(tx.Executor, 5*time.Second),
		sessionrepo.NewRepository(tx.Executor, 5*time.Second), tx, signer, passwords, limiter, requests)
	if err != nil {
		t.Fatal(err)
	}
	current, err := sessioncase.NewService(
		userrepo.NewRepository(tx.Executor, 5*time.Second),
		sessionrepo.NewRepository(tx.Executor, 5*time.Second),
		tx,
		signer,
	)
	if err != nil {
		t.Fatal(err)
	}
	cursors, err := identityhttp.NewCursorCodec([]byte(strings.Repeat("c", 32)))
	if err != nil {
		t.Fatal(err)
	}
	accounts, err := account.NewService(
		userrepo.NewRepository(tx.Executor, 5*time.Second),
		tokens,
		sessionrepo.NewRepository(tx.Executor, 5*time.Second),
		tx,
		passwords,
		requests,
	)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := identityhttp.NewHandler(service, current, verifier, cursors, zap.NewNop(), limiter, requests, accounts)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)
	router, err := identityhttp.NewServer(handler, "https://"+server.Listener.Addr().String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = router
	server.StartTLS()
	mail := &captureMail{}
	delivery, err := email.NewDelivery(
		jobs,
		userrepo.NewRepository(tx.Executor, 5*time.Second),
		tokens,
		tx,
		cipher,
		mail,
		server.URL,
	)
	if err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	client.Timeout = 10 * time.Second
	client.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{
		pool:     pool,
		server:   server,
		client:   client,
		verifier: verifier,
		issuer:   issuer,
		private:  private,
		limiter:  limiter,
		redis:    redisConn,
		accounts: accounts,
		delivery: delivery,
		mail:     mail,
	}
}

type responseInfo struct {
	status  int
	header  http.Header
	cookies []*http.Cookie
}

func (f *fixture) post(
	t *testing.T,
	path, email, value string,
) (responseInfo, []byte) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"email": email, "password": value})
	if err != nil {
		t.Fatal(err)
	}
	r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, f.server.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Origin", f.server.URL)
	r.Header.Set("Content-Type", "application/json")
	response, err := f.client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("auth response can be cached")
	}
	return responseInfo{
		status:  response.StatusCode,
		header:  response.Header,
		cookies: response.Cookies(),
	}, data
}

func (f *fixture) registerUnverified(t *testing.T, email, value string) uuid.UUID {
	t.Helper()
	response, data := f.post(t, "/api/v1/auth/register", email, value)
	if response.status != http.StatusCreated || len(response.cookies) != 0 {
		t.Fatalf("registration status=%d", response.status)
	}
	var body struct {
		UserID string `json:"user_id"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		t.Fatal(err)
	}
	id, err := uuid.Parse(body.UserID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := f.pool.Exec(ctx, `DELETE FROM identity.users WHERE id = $1`, id); err != nil {
			t.Error(err)
		}
	})
	return id
}

func TestRegisterAndLoginThroughHTTPS(t *testing.T) {
	f := newFixture(t, false)
	email := uuid.NewV7().String() + "@EXAMPLE.COM"
	const value = "  длинный пароль с пробелами 🔐  "
	rejected, _ := f.post(t, "/api/v1/auth/register", email, "short")
	if rejected.status != http.StatusBadRequest {
		t.Fatal("weak password accepted")
	}
	id := f.registerVerified(t, email, value)
	response, data := f.post(t, "/api/v1/auth/login", email, value)
	if response.status != http.StatusOK || len(response.header.Values("Set-Cookie")) != 3 {
		t.Fatalf("login status=%d", response.status)
	}
	var body struct {
		UserID           string    `json:"user_id"`
		SessionID        string    `json:"session_id"`
		AccessExpiresAt  time.Time `json:"access_expires_at"`
		SessionExpiresAt time.Time `json:"session_expires_at"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		t.Fatal(err)
	}
	if body.UserID != id.String() {
		t.Fatal("login returned wrong user")
	}
	cookies := make(map[string]*http.Cookie)
	for _, cookie := range response.cookies {
		cookies[cookie.Name] = cookie
		if !cookie.Secure || cookie.Domain != "" || cookie.SameSite != http.SameSiteLaxMode {
			t.Fatal("unsafe cookie scope")
		}
		if strings.Contains(string(data), cookie.Value) {
			t.Fatal("token exposed in JSON")
		}
	}
	access := cookies["__Host-relay_access"]
	refresh := cookies["__Secure-relay_refresh"]
	csrf := cookies["__Host-relay_csrf"]
	if access == nil || refresh == nil || csrf == nil {
		t.Fatal("missing browser cookie")
	}
	if !access.HttpOnly ||
		!refresh.HttpOnly ||
		csrf.HttpOnly ||
		access.Path != "/" ||
		refresh.Path != "/api/v1/auth" ||
		csrf.Path != "/" {
		t.Fatal("incorrect cookie attributes")
	}
	principal, err := f.verifier.Verify(access.Value)
	if err != nil || principal.UserID != id || principal.SessionID.String() != body.SessionID ||
		!principal.ExpiresAt.Equal(body.AccessExpiresAt) || !access.Expires.Equal(principal.ExpiresAt) {
		t.Fatalf("issued access: %v", err)
	}
	csrfHash, err := secret.Digest(csrf.Value)
	if err != nil || principal.CSRFHash != csrfHash {
		t.Fatal("CSRF is not bound to JWT")
	}
	refreshHash, err := secret.Digest(refresh.Value)
	if err != nil {
		t.Fatal(err)
	}
	var storedEmail, hash string
	var storedCSRF []byte
	var sessionExpiry time.Time
	err = f.pool.QueryRow(
		t.Context(),
		`
		SELECT u.email, p.password_hash, s.csrf_hash, s.expires_at
		FROM identity.users u JOIN identity.password_credentials p ON p.user_id = u.id
		JOIN identity.sessions s ON s.user_id = u.id
		JOIN identity.refresh_credentials r ON r.session_id = s.id
		WHERE u.id = $1 AND r.token_hash = $2 AND r.used_at IS NULL`,
		id,
		refreshHash[:],
	).Scan(
		&storedEmail,
		&hash,
		&storedCSRF,
		&sessionExpiry,
	)
	if err != nil ||
		storedEmail != strings.ToLower(email) ||
		!bytes.Equal(storedCSRF, csrfHash[:]) ||
		!sessionExpiry.Truncate(time.Second).Equal(body.SessionExpiresAt) {
		t.Fatalf("stored session: %v", err)
	}
	matched, err := password.Verify(value, hash)
	if err != nil || !matched {
		t.Fatal("password was changed by transport or storage")
	}
	if !refresh.Expires.Equal(sessionExpiry.Truncate(time.Second)) || !csrf.Expires.Equal(refresh.Expires) {
		t.Fatal("cookie exceeds session expiry")
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.server.URL+"/api/v1/items", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, cookie := range f.client.Jar.Cookies(request.URL) {
		if cookie.Name == "__Secure-relay_refresh" {
			t.Fatal("cookie jar sends refresh outside auth path")
		}
	}
}

func TestLoginFailuresThroughHTTPS(t *testing.T) {
	f := newFixture(t, false)
	email := uuid.NewV7().String() + "@example.com"
	const value = "a sufficiently long password"
	id := f.registerVerified(t, email, value)
	for _, attempt := range []struct {
		email    string
		password string
	}{
		{
			email:    email,
			password: "wrong password",
		}, {
			email:    uuid.NewV7().String() + "@example.com",
			password: value,
		},
	} {
		response, data := f.post(t, "/api/v1/auth/login", attempt.email, attempt.password)
		assertInvalidLogin(t, response, data)
	}
	if _, err := f.pool.Exec(t.Context(), `UPDATE identity.users SET state = 'disabled' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	response, data := f.post(t, "/api/v1/auth/login", email, value)
	assertInvalidLogin(t, response, data)
	var count int
	if err := f.pool.QueryRow(
		t.Context(),
		`SELECT count(*) FROM identity.sessions WHERE user_id = $1`,
		id,
	).Scan(&count); err != nil ||
		count != 0 {
		t.Fatalf("failed logins created sessions=%d error=%v", count, err)
	}
}

func assertInvalidLogin(t *testing.T, response responseInfo, data []byte) {
	t.Helper()
	if response.status != http.StatusUnauthorized || len(response.cookies) != 0 {
		t.Fatalf("invalid login status=%d", response.status)
	}
	var body struct {
		Status int    `json:"status"`
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		t.Fatal(err)
	}
	if body.Status != 401 || body.Code != "INVALID_CREDENTIALS" || body.Detail != "Invalid email or password" {
		t.Fatal("login error reveals account state")
	}
}

func TestSigningFailureDoesNotIssueCookies(t *testing.T) {
	f := newFixture(t, true)
	email := uuid.NewV7().String() + "@example.com"
	const value = "a sufficiently long password"
	id := f.registerVerified(t, email, value)
	response, _ := f.post(t, "/api/v1/auth/login", email, value)
	if response.status != http.StatusInternalServerError || len(response.header.Values("Set-Cookie")) != 0 {
		t.Fatalf("failed login status=%d", response.status)
	}
	var count int
	if err := f.pool.QueryRow(
		t.Context(),
		`SELECT count(*) FROM identity.sessions WHERE user_id = $1`,
		id,
	).Scan(&count); err != nil ||
		count != 0 {
		t.Fatalf("failed signing left sessions=%d error=%v", count, err)
	}
}

func (f *fixture) registerVerified(t *testing.T, email, password string) uuid.UUID {
	t.Helper()
	id := f.registerUnverified(t, email, password)
	f.verifyRegistered(t, email)
	return id
}
