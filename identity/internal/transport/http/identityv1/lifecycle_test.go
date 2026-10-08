package identityv1

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"uuid"

	"go.uber.org/zap"

	"github.com/horizoonn/relay/identity/internal/secret"
	"github.com/horizoonn/relay/identity/internal/usecase/session"
)

func TestRefreshAndLogoutResponses(t *testing.T) {
	refresh, err := secret.Generate()
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := secret.Generate()
	if err != nil {
		t.Fatal(err)
	}
	cookies := refreshCookieName + "=" + refresh + "; " + csrfCookieName + "=" + csrf
	for _, tc := range []struct {
		name       string
		method     string
		origin     string
		cookie     string
		header     string
		serviceErr error
		status     int
		called     bool
	}{
		{
			name:       "refresh",
			method:     "POST",
			origin:     testOrigin,
			cookie:     cookies,
			header:     csrf,
			serviceErr: nil,
			status:     200,
			called:     true,
		},
		{
			name:       "refresh conflict",
			method:     "POST",
			origin:     testOrigin,
			cookie:     cookies,
			header:     csrf,
			serviceErr: session.ErrRefreshConflict,
			status:     409,
			called:     true,
		},
		{
			name:       "replay",
			method:     "POST",
			origin:     testOrigin,
			cookie:     cookies,
			header:     csrf,
			serviceErr: session.ErrUnauthenticated,
			status:     401,
			called:     true,
		},
		{
			name:       "stored CSRF mismatch",
			method:     "POST",
			origin:     testOrigin,
			cookie:     cookies,
			header:     csrf,
			serviceErr: session.ErrCSRF,
			status:     403,
			called:     true,
		},
		{
			name:       "storage error",
			method:     "POST",
			origin:     testOrigin,
			cookie:     cookies,
			header:     csrf,
			serviceErr: errors.New("private database info"),
			status:     500,
			called:     true,
		},
		{
			name:       "missing refresh",
			method:     "POST",
			origin:     testOrigin,
			cookie:     "",
			header:     "",
			serviceErr: nil,
			status:     401,
			called:     false,
		},
		{
			name:       "missing Origin",
			method:     "POST",
			origin:     "",
			cookie:     cookies,
			header:     csrf,
			serviceErr: nil,
			status:     403,
			called:     false,
		},
		{
			name:       "foreign Origin",
			method:     "POST",
			origin:     "https://evil.example",
			cookie:     cookies,
			header:     csrf,
			serviceErr: nil,
			status:     403,
			called:     false,
		},
		{
			name:       "missing header",
			method:     "POST",
			origin:     testOrigin,
			cookie:     cookies,
			header:     "",
			serviceErr: nil,
			status:     403,
			called:     false,
		},
		{
			name:       "wrong header",
			method:     "POST",
			origin:     testOrigin,
			cookie:     cookies,
			header:     "wrong",
			serviceErr: nil,
			status:     403,
			called:     false,
		},
		{
			name:       "missing CSRF cookie",
			method:     "POST",
			origin:     testOrigin,
			cookie:     refreshCookieName + "=" + refresh,
			header:     csrf,
			serviceErr: nil,
			status:     403,
			called:     false,
		},
		{
			name:       "duplicate cookie",
			method:     "POST",
			origin:     testOrigin,
			cookie:     cookies + "; " + refreshCookieName + "=" + refresh,
			header:     csrf,
			serviceErr: nil,
			status:     400,
			called:     false,
		},
		{
			name:       "logout",
			method:     "DELETE",
			origin:     testOrigin,
			cookie:     cookies,
			header:     csrf,
			serviceErr: nil,
			status:     204,
			called:     true,
		},
		{
			name:       "logout without session",
			method:     "DELETE",
			origin:     testOrigin,
			cookie:     "",
			header:     "",
			serviceErr: nil,
			status:     204,
			called:     true,
		},
		{
			name:       "logout wrong CSRF",
			method:     "DELETE",
			origin:     testOrigin,
			cookie:     cookies,
			header:     "wrong",
			serviceErr: nil,
			status:     403,
			called:     false,
		},
		{
			name:       "logout foreign Origin",
			method:     "DELETE",
			origin:     "https://evil.example",
			cookie:     cookies,
			header:     csrf,
			serviceErr: nil,
			status:     403,
			called:     false,
		},
		{
			name:       "logout storage error",
			method:     "DELETE",
			origin:     testOrigin,
			cookie:     cookies,
			header:     csrf,
			serviceErr: errors.New("private database info"),
			status:     500,
			called:     true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			svc := fakeSessions{
				refresh: func(_ context.Context, raw, value string) (session.RefreshResult, error) {
					called = true
					if raw != refresh || value != csrf {
						t.Fatal("wrong refresh or CSRF passed to use case")
					}
					return session.RefreshResult{
						UserID:           uuid.NewV7(),
						SessionID:        uuid.NewV7(),
						AccessToken:      "signed-access",
						RefreshToken:     "next-refresh",
						AccessExpiresAt:  time.Now().Add(time.Minute),
						SessionExpiresAt: time.Now().Add(time.Hour),
					}, tc.serviceErr
				},
				logout: func(context.Context, string, string) error { called = true; return tc.serviceErr },
			}
			h, err := NewHandler(
				fakeAuth{},
				svc,
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
			server, err := NewServer(h, testOrigin, nil)
			if err != nil {
				t.Fatal(err)
			}
			path := "/api/v1/auth/refresh"
			if tc.method == "DELETE" {
				path = "/api/v1/auth/session"
			}
			r := httptest.NewRequestWithContext(t.Context(), tc.method, path, nil)
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if tc.cookie != "" {
				r.Header.Set("Cookie", tc.cookie)
			}
			if tc.header != "" {
				r.Header.Set("X-CSRF-Token", tc.header)
			}
			w := httptest.NewRecorder()
			server.ServeHTTP(w, r)
			if w.Code != tc.status || called != tc.called {
				t.Fatalf("status=%d called=%t", w.Code, called)
			}
			assertPrivateResponse(t, w)
			if tc.status >= 400 && len(w.Header().Values("Set-Cookie")) != 0 {
				t.Fatal("failure changed browser cookies")
			}
			if tc.status == 204 {
				response := w.Result()
				defer func() { _ = response.Body.Close() }()
				cleared := response.Cookies()
				if len(cleared) != 3 || w.Body.Len() != 0 {
					t.Fatal("logout did not clear three cookies without a body")
				}
				for _, c := range cleared {
					path := "/"
					if c.Name == refreshCookieName {
						path = "/api/v1/auth"
					}
					if c.Value != "" ||
						c.MaxAge != -1 ||
						!c.Expires.Before(time.Now()) ||
						c.Path != path ||
						c.Domain != "" ||
						!c.Secure {
						t.Fatal("incorrect cookie deletion scope")
					}
				}
			}
			if tc.status == 200 {
				if len(w.Header().Values("Set-Cookie")) != 3 || !strings.Contains(w.Header().Get("Set-Cookie"), "signed-access") {
					t.Fatal("refresh did not issue cookies")
				}
			}
			for _, value := range []string{refresh, csrf, "signed-access", "next-refresh", "private database info"} {
				if strings.Contains(w.Body.String(), value) {
					t.Fatal("response exposed credential or internal details")
				}
			}
		})
	}
}

func TestRefreshAndLogoutRejectInvalidRequests(t *testing.T) {
	for _, method := range []string{"POST", "DELETE"} {
		path := "/api/v1/auth/refresh"
		if method == "DELETE" {
			path = "/api/v1/auth/session"
		}
		for _, kind := range []string{"origin", "csrf", "body"} {
			t.Run(method+kind, func(t *testing.T) {
				body := ""
				if kind == "body" {
					body = "{}"
				}
				r := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
				r.Header.Set("Origin", testOrigin)
				r.Header.Set("Cookie", refreshCookieName+"=refresh; "+csrfCookieName+"=csrf")
				r.Header.Set("X-CSRF-Token", "csrf")
				if kind == "origin" {
					r.Header.Add("Origin", testOrigin)
				}
				if kind == "csrf" {
					r.Header.Add("X-CSRF-Token", "csrf")
				}
				w := httptest.NewRecorder()
				testServer(t, fakeAuth{}, &strings.Builder{}).ServeHTTP(w, r)
				want := 403
				if kind == "body" {
					want = 400
				}
				if w.Code != want || len(w.Header().Values("Set-Cookie")) != 0 {
					t.Fatalf("ambiguous request status=%d", w.Code)
				}
			})
		}
	}
}
