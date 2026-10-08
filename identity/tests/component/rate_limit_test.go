//go:build component

package component

import (
	"bytes"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/platform/pkg/ratelimit"
	identityapi "github.com/horizoonn/relay/shared/pkg/openapi/identity/v1"

	identitylimit "github.com/horizoonn/relay/identity/internal/ratelimit"
)

func rateRequest(
	t *testing.T,
	f *fixture,
	method, path string,
	body []byte,
	cookies []*http.Cookie,
) (int, http.Header, []byte) {
	t.Helper()
	r, err := http.NewRequestWithContext(t.Context(), method, f.server.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Origin", f.server.URL)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	for _, cookie := range cookies {
		r.AddCookie(cookie)
		if cookie.Name == "__Host-relay_csrf" {
			r.Header.Set("X-CSRF-Token", cookie.Value)
		}
	}
	response, err := f.client.Do(r)
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

func rateSession(t *testing.T, f *fixture) ([]byte, []*http.Cookie) {
	t.Helper()
	email := uuid.NewV7().String() + "@example.com"
	password := "correct password with sufficient length"
	registration, _ := f.post(t, "/api/v1/auth/register", email, password)
	if registration.status != 201 {
		t.Fatalf("registration=%d", registration.status)
	}
	f.verifyRegistered(t, email)
	login, _ := f.post(t, "/api/v1/auth/login", email, password)
	if login.status != 200 {
		t.Fatalf("login=%d", login.status)
	}
	endpoint, err := url.Parse(f.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	endpoint.Path = "/api/v1/auth/session"
	cookies := f.client.Jar.Cookies(endpoint)

	f.client.Jar = nil
	body, err := json.Marshal(map[string]string{"email": email, "password": password})
	if err != nil {
		t.Fatal(err)
	}
	return body, cookies
}

func TestRateLimitedIdentityRoutes(t *testing.T) {
	for _, tc := range []struct {
		name        string
		method      string
		path        string
		scope       identitylimit.Scope
		usedBySetup bool
		firstStatus int
	}{
		{
			name:        "register",
			method:      http.MethodPost,
			path:        "/api/v1/auth/register",
			scope:       identitylimit.RegisterIP,
			usedBySetup: true,
			firstStatus: 0,
		},
		{
			name:        "login IP",
			method:      http.MethodPost,
			path:        "/api/v1/auth/login",
			scope:       identitylimit.LoginIP,
			usedBySetup: true,
			firstStatus: 0,
		},
		{
			name:        "login account",
			method:      http.MethodPost,
			path:        "/api/v1/auth/login",
			scope:       identitylimit.LoginAccount,
			usedBySetup: true,
			firstStatus: 0,
		},
		{
			name:        "refresh",
			method:      http.MethodPost,
			path:        "/api/v1/auth/refresh",
			scope:       identitylimit.RefreshIP,
			usedBySetup: false,
			firstStatus: 200,
		},
		{
			name:        "current session",
			method:      http.MethodGet,
			path:        "/api/v1/auth/session",
			scope:       identitylimit.ReadUser,
			usedBySetup: false,
			firstStatus: 200,
		},
		{
			name:        "session list",
			method:      http.MethodGet,
			path:        "/api/v1/auth/sessions",
			scope:       identitylimit.ReadUser,
			usedBySetup: false,
			firstStatus: 200,
		},
		{
			name:        "logout",
			method:      http.MethodDelete,
			path:        "/api/v1/auth/session",
			scope:       identitylimit.LogoutIP,
			usedBySetup: false,
			firstStatus: 204,
		},
		{
			name:        "revoke all",
			method:      http.MethodDelete,
			path:        "/api/v1/auth/sessions",
			scope:       identitylimit.RevokeUser,
			usedBySetup: false,
			firstStatus: 204,
		},
		{
			name:        "revoke selected",
			method:      http.MethodDelete,
			path:        "selected",
			scope:       identitylimit.RevokeUser,
			usedBySetup: false,
			firstStatus: 204,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixtureWithRules(t, false, map[identitylimit.Scope]ratelimit.Rule{tc.scope: {
				Rate:   1,
				Period: time.Hour,
				Burst:  1,
			}})
			body, cookies := rateSession(t, f)
			if tc.path == "selected" {
				for _, cookie := range cookies {
					if cookie.Name == "__Host-relay_access" {
						access, err := f.verifier.Verify(cookie.Value)
						if err != nil {
							t.Fatal(err)
						}
						tc.path = "/api/v1/auth/sessions/" + access.SessionID.String()
					}
				}
			}
			if tc.method != http.MethodPost || tc.scope == identitylimit.RefreshIP {
				body = nil
			}
			if !tc.usedBySetup {
				status, _, _ := rateRequest(t, f, tc.method, tc.path, body, cookies)
				if status != tc.firstStatus {
					t.Fatalf("first status=%d want=%d", status, tc.firstStatus)
				}
			}
			status, header, data := rateRequest(t, f, tc.method, tc.path, body, cookies)
			var problem identityapi.Problem
			if err := json.Unmarshal(data, &problem); err != nil {
				t.Fatal(err)
			}
			if status != 429 ||
				problem.Status != 429 ||
				problem.Code != identityapi.ProblemCodeRATELIMITED ||
				header.Get("Retry-After") == "" ||
				len(header.Values("Set-Cookie")) != 0 {
				t.Fatalf("status=%d problem=%v header=%v", status, problem, header)
			}
		})
	}
}

func TestSessionOperationsWithoutRedis(t *testing.T) {
	f := newFixture(t, false)
	body, cookies := rateSession(t, f)
	if err := f.redis.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/auth/register", "/api/v1/auth/login", "/api/v1/auth/refresh"} {
		t.Run(path, func(t *testing.T) {
			payload := body
			if path == "/api/v1/auth/refresh" {
				payload = nil
			}
			status, header, data := rateRequest(t, f, http.MethodPost, path, payload, cookies)
			var problem identityapi.Problem
			if err := json.Unmarshal(data, &problem); err != nil {
				t.Fatal(err)
			}
			if status != 503 ||
				problem.Code != identityapi.ProblemCodeSERVICEUNAVAILABLE ||
				len(header.Values("Set-Cookie")) != 0 {
				t.Fatalf("status=%d body=%s", status, data)
			}
		})
	}
	for _, path := range []string{"/api/v1/auth/session", "/api/v1/auth/sessions"} {
		status, _, _ := rateRequest(t, f, http.MethodGet, path, nil, cookies)
		if status != 200 {
			t.Fatalf("read %s status=%d", path, status)
		}
	}
	status, header, _ := rateRequest(t, f, http.MethodDelete, "/api/v1/auth/sessions", nil, cookies)
	if status != 204 || len(header.Values("Set-Cookie")) != 3 {
		t.Fatalf("revoke all status=%d header=%v", status, header)
	}
}
