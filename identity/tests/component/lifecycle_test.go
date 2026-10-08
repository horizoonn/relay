//go:build component

package component

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"uuid"
)

func (f *fixture) mutateSession(t *testing.T, method, csrf string) (responseInfo, []byte) {
	t.Helper()
	path := "/api/v1/auth/refresh"
	if method == http.MethodDelete {
		path = "/api/v1/auth/session"
	}
	r, err := http.NewRequestWithContext(t.Context(), method, f.server.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Origin", f.server.URL)
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
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
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("session mutation can be cached")
	}
	return responseInfo{
		status:  response.StatusCode,
		header:  response.Header,
		cookies: response.Cookies(),
	}, data
}

func TestRefreshLogoutThroughHTTPS(t *testing.T) {
	f := newFixture(t, false)
	browserURL, err := url.Parse(f.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	email := uuid.NewV7().String() + "@example.com"
	f.registerVerified(t, email, "refresh lifecycle password")
	login, _ := f.post(t, "/api/v1/auth/login", email, "refresh lifecycle password")
	if login.status != 200 {
		t.Fatal("login failed")
	}
	var csrf, original, oldAccess string
	for _, c := range login.cookies {
		switch c.Name {
		case "__Host-relay_csrf":
			csrf = c.Value
		case "__Secure-relay_refresh":
			original = c.Value
		case "__Host-relay_access":
			oldAccess = c.Value
		}
	}

	f.client.Jar.SetCookies(browserURL, []*http.Cookie{{
		Name:   "__Host-relay_access",
		Path:   "/",
		MaxAge: -1,
	}})
	bad, _ := f.mutateSession(t, http.MethodPost, "wrong")
	if bad.status != 403 || len(bad.cookies) != 0 {
		t.Fatal("CSRF rejection changed cookies")
	}
	rotated, data := f.mutateSession(t, http.MethodPost, csrf)
	if rotated.status != 200 || len(rotated.cookies) != 3 {
		t.Fatalf("refresh status=%d", rotated.status)
	}
	var next, access string
	for _, c := range rotated.cookies {
		if c.Name == "__Secure-relay_refresh" {
			next = c.Value
		}
		if c.Name == "__Host-relay_access" {
			access = c.Value
		}
		if c.Name == "__Host-relay_csrf" && c.Value != csrf {
			t.Fatal("refresh changed CSRF")
		}
	}
	if next == "" || next == original || strings.Contains(string(data), next) || strings.Contains(string(data), csrf) {
		t.Fatal("refresh did not rotate privately")
	}
	if _, err := f.verifier.Verify(access); err != nil {
		t.Fatal(err)
	}

	f.client.Jar.SetCookies(browserURL, []*http.Cookie{{
		Name:   "__Secure-relay_refresh",
		Value:  original,
		Path:   "/api/v1/auth",
		Secure: true,
	}})
	conflict, _ := f.mutateSession(t, http.MethodPost, csrf)
	if conflict.status != 409 || len(conflict.cookies) != 0 {
		t.Fatal("early replay did not preserve cookies")
	}

	logout, body := f.mutateSession(t, http.MethodDelete, csrf)
	if logout.status != 204 || len(logout.cookies) != 3 || len(body) != 0 {
		t.Fatalf("logout status=%d", logout.status)
	}
	if status, _ := f.currentSession(t, "__Host-relay_access="+access); status != 401 {
		t.Fatal("session remains active after logout")
	}
	if _, err := f.verifier.Verify(oldAccess); err != nil {
		t.Fatal("logout changed cryptographic validity of the old access")
	}
	f.client.Jar.SetCookies(browserURL, []*http.Cookie{
		{
			Name:   "__Secure-relay_refresh",
			Value:  next,
			Path:   "/api/v1/auth",
			Secure: true,
		},
		{
			Name:   "__Host-relay_csrf",
			Value:  csrf,
			Path:   "/",
			Secure: true,
		},
	})
	rejected, _ := f.mutateSession(t, http.MethodPost, csrf)
	if rejected.status != 401 || len(rejected.cookies) != 0 {
		t.Fatal("new refresh survived logout")
	}
	f.client.Jar.SetCookies(browserURL, []*http.Cookie{{
		Name:   "__Secure-relay_refresh",
		Path:   "/api/v1/auth",
		MaxAge: -1,
	}})
	emptyLogout, _ := f.mutateSession(t, http.MethodDelete, "")
	if emptyLogout.status != 204 || len(emptyLogout.cookies) != 3 {
		t.Fatal("logout without a credential did not clear cookies")
	}
}
