package identityv1

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/platform/pkg/security/accessjwt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/horizoonn/relay/identity/internal/domain"
	"github.com/horizoonn/relay/identity/internal/password"
	identitylimit "github.com/horizoonn/relay/identity/internal/ratelimit"
	"github.com/horizoonn/relay/identity/internal/usecase/account"
	"github.com/horizoonn/relay/identity/internal/usecase/auth"
	"github.com/horizoonn/relay/identity/internal/usecase/session"
)

const testOrigin = "https://relay.example"

type fakeAuth struct {
	register func(context.Context, string, string) (uuid.UUID, error)
	login    func(context.Context, string, string) (auth.LoginResult, error)
}

type fakeSessions struct {
	list      func(context.Context, uuid.UUID, uuid.UUID, session.ListParams) (session.Page, error)
	revoke    func(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string) error
	revokeAll func(context.Context, uuid.UUID, uuid.UUID, string) error
	current   func(context.Context, uuid.UUID, uuid.UUID) (session.Current, error)
	refresh   func(context.Context, string, string) (session.RefreshResult, error)
	logout    func(context.Context, string, string) error
}

func (f fakeSessions) Refresh(ctx context.Context, raw, csrf string) (session.RefreshResult, error) {
	return f.refresh(ctx, raw, csrf)
}

func (f fakeSessions) Logout(ctx context.Context, raw, csrf string) error {
	return f.logout(ctx, raw, csrf)
}

func (f fakeSessions) GetCurrent(ctx context.Context, u, s uuid.UUID) (session.Current, error) {
	return f.current(ctx, u, s)
}

func (f fakeSessions) ListActive(
	ctx context.Context,
	u, caller uuid.UUID,
	params session.ListParams,
) (session.Page, error) {
	return f.list(ctx, u, caller, params)
}

func (f fakeSessions) Revoke(ctx context.Context, u, caller, target uuid.UUID, csrf string) error {
	return f.revoke(ctx, u, caller, target, csrf)
}

func (f fakeSessions) RevokeAll(ctx context.Context, u, caller uuid.UUID, csrf string) error {
	return f.revokeAll(ctx, u, caller, csrf)
}

func testCursors(t *testing.T) *CursorCodec {
	t.Helper()
	codec, err := NewCursorCodec([]byte(strings.Repeat("c", 32)))
	if err != nil {
		t.Fatal(err)
	}
	return codec
}

type rejectingVerifier struct{}

func (rejectingVerifier) Verify(string) (accessjwt.Access, error) {
	return accessjwt.Access{}, accessjwt.ErrInvalidToken
}

func (f fakeAuth) Register(ctx context.Context, email, password string) (uuid.UUID, error) {
	return f.register(ctx, email, password)
}

func (f fakeAuth) Login(ctx context.Context, email, password string) (auth.LoginResult, error) {
	return f.login(ctx, email, password)
}

func testServer(t *testing.T, service fakeAuth, logs io.Writer) http.Handler {
	t.Helper()
	handler, err := NewHandler(
		service,
		fakeSessions{},
		rejectingVerifier{},
		testCursors(t),
		testLogger(logs),
		unlimitedLimiter{},
		fakeAccounts{},
		fakeAccounts{},
	)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(handler, testOrigin, nil)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func testLogger(writer io.Writer) *zap.Logger {
	return zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(writer),
		zap.DebugLevel,
	))
}

func authRequest(t *testing.T, path, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Origin", testOrigin)
	r.Header.Set("Content-Type", "application/json")
	return r
}

func TestRegisterResponse(t *testing.T) {
	id := uuid.NewV7()
	service := fakeAuth{
		register: func(_ context.Context, email, password string) (uuid.UUID, error) {
			if email != "User@EXAMPLE.COM" || password != "  пароль с пробелами 🔐  " {
				t.Fatal("transport modified credentials")
			}
			return id, nil
		},
	}
	response := httptest.NewRecorder()
	testServer(t, service, io.Discard).ServeHTTP(response, authRequest(t,
		"/api/v1/auth/register", `{"email":"User@EXAMPLE.COM","password":"  пароль с пробелами 🔐  "}`))
	if response.Code != http.StatusCreated || len(response.Header().Values("Set-Cookie")) != 0 {
		t.Fatalf("registration status=%d", response.Code)
	}
	var body struct {
		UserID string `json:"user_id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.UserID != id.String() {
		t.Fatalf("registration response: %v", err)
	}
	assertPrivateResponse(t, response)
}

func TestLoginCookieResponse(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	result := auth.LoginResult{
		UserID:           uuid.NewV7(),
		SessionID:        uuid.NewV7(),
		AccessExpiresAt:  now.Add(5 * time.Minute),
		SessionExpiresAt: now.Add(domain.MaxSessionLifetime),
		AccessToken:      "access-token",
		RefreshToken:     "refresh-secret",
		CSRFToken:        "csrf-secret",
	}
	service := fakeAuth{
		login: func(context.Context, string, string) (auth.LoginResult, error) { return result, nil },
	}
	response := httptest.NewRecorder()
	testServer(t, service, io.Discard).ServeHTTP(response, authRequest(t, "/api/v1/auth/login",
		`{"email":"user@example.com","password":"a sufficiently long password"}`))
	if response.Code != http.StatusOK || len(response.Header().Values("Set-Cookie")) != 3 {
		t.Fatalf("login status=%d cookie fields=%d", response.Code, len(response.Header().Values("Set-Cookie")))
	}
	res := response.Result()
	defer func() {
		if err := res.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	cookies := res.Cookies()
	for i, expected := range []struct {
		name     string
		value    string
		path     string
		httpOnly bool
		expiry   time.Time
	}{
		{
			name:     "__Host-relay_access",
			value:    result.AccessToken,
			path:     "/",
			httpOnly: true,
			expiry:   result.AccessExpiresAt,
		},
		{
			name:     "__Secure-relay_refresh",
			value:    result.RefreshToken,
			path:     "/api/v1/auth",
			httpOnly: true,
			expiry:   result.SessionExpiresAt,
		},
		{
			name:     "__Host-relay_csrf",
			value:    result.CSRFToken,
			path:     "/",
			httpOnly: false,
			expiry:   result.SessionExpiresAt,
		},
	} {
		cookie := cookies[i]
		if cookie.Name != expected.name || cookie.Value != expected.value || cookie.Path != expected.path ||
			cookie.HttpOnly != expected.httpOnly || !cookie.Secure || cookie.Domain != "" ||
			cookie.SameSite != http.SameSiteLaxMode || !cookie.Expires.Equal(expected.expiry) {
			t.Fatalf("incorrect cookie policy for %s", expected.name)
		}
	}
	for _, token := range []string{result.AccessToken, result.RefreshToken, result.CSRFToken} {
		if strings.Contains(response.Body.String(), token) {
			t.Fatal("credential exposed in JSON")
		}
	}
	var body struct {
		AccessExpiresAt  time.Time `json:"access_expires_at"`
		SessionExpiresAt time.Time `json:"session_expires_at"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil ||
		!body.AccessExpiresAt.Equal(result.AccessExpiresAt) || !body.SessionExpiresAt.Equal(result.SessionExpiresAt) {
		t.Fatalf("response expiry: %v", err)
	}
	assertPrivateResponse(t, response)
}

func TestRegisterAndLoginRejectInvalidRequests(t *testing.T) {
	for _, test := range []struct {
		name   string
		edit   func(*http.Request)
		status int
		code   string
	}{
		{
			name: "missing origin",
			edit: func(r *http.Request) {
				r.Header.Del("Origin")
			},
			status: 403,
			code:   "FORBIDDEN",
		},
		{
			name: "foreign origin",
			edit: func(r *http.Request) {
				r.Header.Set("Origin", "https://attacker.example")
			},
			status: 403,
			code:   "FORBIDDEN",
		},
		{
			name: "null origin",
			edit: func(r *http.Request) {
				r.Header.Set("Origin", "null")
			},
			status: 403,
			code:   "FORBIDDEN",
		},
		{
			name: "duplicate origin",
			edit: func(r *http.Request) {
				r.Header.Add("Origin", testOrigin)
			},
			status: 403,
			code:   "FORBIDDEN",
		},
		{
			name: "origin suffix",
			edit: func(r *http.Request) {
				r.Header.Set("Origin", testOrigin+".attacker.example")
			},
			status: 403,
			code:   "FORBIDDEN",
		},
		{
			name: "missing content type",
			edit: func(r *http.Request) {
				r.Header.Del("Content-Type")
			},
			status: 415,
			code:   "UNSUPPORTED_MEDIA_TYPE",
		},
		{
			name: "wrong content type",
			edit: func(r *http.Request) {
				r.Header.Set("Content-Type", "text/plain")
			},
			status: 415,
			code:   "UNSUPPORTED_MEDIA_TYPE",
		},
		{
			name: "duplicate content type",
			edit: func(r *http.Request) {
				r.Header.Add("Content-Type", "application/json")
			},
			status: 415,
			code:   "UNSUPPORTED_MEDIA_TYPE",
		},
		{
			name: "malformed json",
			edit: func(r *http.Request) {
				r.Body = io.NopCloser(strings.NewReader("{"))
			},
			status: 400,
			code:   "INVALID_REQUEST",
		},
		{
			name: "missing password",
			edit: func(r *http.Request) {
				r.Body = io.NopCloser(strings.NewReader(`{"email":"user@example.com"}`))
			},
			status: 400,
			code:   "INVALID_REQUEST",
		},
		{
			name: "unknown field",
			edit: func(r *http.Request) {
				r.Body = io.NopCloser(strings.NewReader(
					`{"email":"user@example.com","password":"long password value","user_id":"fake"}`,
				))
			},
			status: 400,
			code:   "INVALID_REQUEST",
		},
		{
			name: "trailing json",
			edit: func(r *http.Request) {
				r.Body = io.NopCloser(strings.NewReader(`{"email":"user@example.com","password":"long password value"}{}`))
			},
			status: 400,
			code:   "INVALID_REQUEST",
		},
		{
			name: "oversized body",
			edit: func(r *http.Request) {
				r.Body = io.NopCloser(strings.NewReader(strings.Repeat(" ", 4097)))
			},
			status: 413,
			code:   "PAYLOAD_TOO_LARGE",
		},
		{
			name: "duplicate access cookie",
			edit: func(r *http.Request) {
				r.Header.Set("Cookie", "__Host-relay_access=one; __Host-relay_access=two")
			},
			status: 400,
			code:   "INVALID_REQUEST",
		},
	} {
		for _, path := range []string{"/api/v1/auth/register", "/api/v1/auth/login"} {
			t.Run(strings.TrimPrefix(path, "/api/v1/auth/")+"/"+test.name, func(t *testing.T) {
				called := false
				service := fakeAuth{
					register: func(context.Context, string, string) (uuid.UUID, error) { called = true; return uuid.Nil(), nil },
					login: func(context.Context, string, string) (auth.LoginResult, error) {
						called = true
						return auth.LoginResult{}, nil
					},
				}
				request := authRequest(t, path, `{"email":"user@example.com","password":"long password value"}`)
				test.edit(request)
				response := httptest.NewRecorder()
				testServer(t, service, io.Discard).ServeHTTP(response, request)
				assertProblem(t, response, test.status, test.code)
				if called {
					t.Fatal("rejected request reached use case")
				}
			})
		}
	}
}

func TestUsecaseErrorsDoNotExposeCredentials(t *testing.T) {
	for _, test := range []struct {
		err    error
		status int
		code   string
	}{
		{
			err:    domain.ErrInvalidEmail,
			status: 400,
			code:   "INVALID_REQUEST",
		},
		{
			err:    password.ErrInvalidPassword,
			status: 400,
			code:   "INVALID_REQUEST",
		},
		{
			err:    domain.ErrEmailAlreadyRegistered,
			status: 409,
			code:   "REGISTRATION_CONFLICT",
		},
		{
			err:    auth.ErrInvalidCredentials,
			status: 401,
			code:   "INVALID_CREDENTIALS",
		},
		{
			err:    fmt.Errorf("register account transaction: %w", domain.ErrEmailAlreadyRegistered),
			status: 409,
			code:   "REGISTRATION_CONFLICT",
		},
		{
			err:    fmt.Errorf("complete login transaction: %w", auth.ErrInvalidCredentials),
			status: 401,
			code:   "INVALID_CREDENTIALS",
		},
		{
			err:    fmt.Errorf("refresh session transaction: %w", session.ErrRefreshConflict),
			status: 409,
			code:   "REFRESH_CONFLICT",
		},
		{
			err:    fmt.Errorf("revoke session transaction: %w", session.ErrCSRF),
			status: 403,
			code:   "FORBIDDEN",
		},
		{
			err:    fmt.Errorf("revoke session transaction: %w", session.ErrSessionNotFound),
			status: 404,
			code:   "SESSION_NOT_FOUND",
		},
		{
			err:    fmt.Errorf("verify account email transaction: %w", account.ErrInvalidToken),
			status: 400,
			code:   "INVALID_TOKEN",
		},
		{
			err:    errors.New("sensitive-password user@example.com"),
			status: 500,
			code:   "INTERNAL_ERROR",
		},
		{
			err:    fmt.Errorf("load password credentials: %w", errors.New("sensitive-password user@example.com")),
			status: 500,
			code:   "INTERNAL_ERROR",
		},
	} {
		t.Run(test.code, func(t *testing.T) {
			var logs bytes.Buffer
			service := fakeAuth{
				login: func(context.Context, string, string) (auth.LoginResult, error) { return auth.LoginResult{}, test.err },
			}
			response := httptest.NewRecorder()
			testServer(t, service, &logs).ServeHTTP(
				response,
				authRequest(
					t,
					"/api/v1/auth/login",
					`{"email":"user@example.com","password":"sensitive-password"}`,
				),
			)
			assertProblem(t, response, test.status, test.code)
			for _, output := range []string{response.Body.String(), logs.String()} {
				if strings.Contains(output, "sensitive-password") || strings.Contains(output, "user@example.com") {
					t.Fatal("credential or identifier exposed")
				}
			}
		})
	}
}

func TestNewServerRejectsInvalidConfiguration(t *testing.T) {
	handler, err := NewHandler(
		fakeAuth{},
		fakeSessions{},
		rejectingVerifier{},
		testCursors(t),
		zap.NewNop(),
		unlimitedLimiter{},
		fakeAccounts{},
		fakeAccounts{},
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{
		"",
		"*",
		"http://relay.example",
		testOrigin + "/",
		testOrigin + "?x=1",
		"https://user@relay.example",
	} {
		if _, err := NewServer(handler, origin, nil); err == nil {
			t.Fatalf("accepted origin %q", origin)
		}
	}
	if _, err := NewHandler(
		nil,
		fakeSessions{},
		rejectingVerifier{},
		testCursors(t),
		zap.NewNop(),
		unlimitedLimiter{},
		fakeAccounts{},
		fakeAccounts{},
	); err == nil {
		t.Fatal("nil auth service accepted")
	}
	if _, err := NewServer(nil, testOrigin, nil); err == nil {
		t.Fatal("nil handler accepted")
	}
}

func TestServerRoutingErrors(t *testing.T) {
	server := testServer(t, fakeAuth{}, io.Discard)
	for _, test := range []struct {
		method string
		path   string
		status int
		code   string
	}{
		{
			method: http.MethodGet,
			path:   "/api/v1/auth/missing",
			status: 404,
			code:   "ROUTE_NOT_FOUND",
		},
		{
			method: http.MethodGet,
			path:   "/api/v1/auth/login",
			status: 405,
			code:   "METHOD_NOT_ALLOWED",
		},
	} {
		response := httptest.NewRecorder()
		server.ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), test.method, test.path, nil))
		assertProblem(t, response, test.status, test.code)
		if test.status == 405 && response.Header().Get("Allow") != "POST" {
			t.Fatal("missing Allow header")
		}
	}
}

func assertPrivateResponse(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Request-ID") == "" {
		t.Fatal("missing privacy or correlation headers")
	}
}

func assertProblem(
	t *testing.T,
	response *httptest.ResponseRecorder,
	status int,
	code string,
) {
	t.Helper()
	if response.Code != status || response.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("status/type=%d/%s want %d/problem+json", response.Code, response.Header().Get("Content-Type"), status)
	}
	var body struct {
		Status    int    `json:"status"`
		Code      string `json:"code"`
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Status != status || body.Code != code || body.RequestID != response.Header().Get("X-Request-ID") {
		t.Fatalf("inconsistent Problem response: %+v", body)
	}
	if len(response.Header().Values("Set-Cookie")) != 0 {
		t.Fatal("error response issued cookies")
	}
	assertPrivateResponse(t, response)
}

func TestProblemEscapesHTMLInRequestID(t *testing.T) {
	t.Parallel()
	request := authRequest(t, "/api/v1/auth/login", `{"email":"user@example.com","password":"long password value"}`)
	request.Header.Set("Origin", "https://foreign.example")
	request.Header.Set("X-Request-ID", "<script>alert(1)</script>")
	response := httptest.NewRecorder()
	testServer(t, fakeAuth{}, io.Discard).ServeHTTP(response, request)
	assertProblem(t, response, 403, "FORBIDDEN")
	if strings.Contains(response.Body.String(), "<script>") ||
		response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("Problem response did not escape HTML or disable content sniffing")
	}
}

type unlimitedLimiter struct{}

func (unlimitedLimiter) Allow(context.Context, identitylimit.Scope, string) error { return nil }
