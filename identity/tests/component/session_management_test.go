//go:build component

package component

import (
	"encoding/json/v2"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"uuid"
)

const managementPassword = "session management browser password"

type browserSession struct {
	id      uuid.UUID
	access  string
	csrf    string
	refresh string
}

func (f *fixture) loginSession(t *testing.T, email string) browserSession {
	t.Helper()
	response, _ := f.post(t, "/api/v1/auth/login", email, managementPassword)
	if response.status != http.StatusOK {
		t.Fatalf("login status=%d", response.status)
	}
	var session browserSession
	for _, cookie := range response.cookies {
		switch cookie.Name {
		case "__Host-relay_access":
			session.access = cookie.Value
		case "__Host-relay_csrf":
			session.csrf = cookie.Value
		case "__Secure-relay_refresh":
			session.refresh = cookie.Value
		}
	}
	access, err := f.verifier.Verify(session.access)
	if err != nil {
		t.Fatal(err)
	}
	session.id = access.SessionID
	return session
}

func (f *fixture) managementRequest(
	t *testing.T,
	method, path string,
	session browserSession,
	csrf string,
) (responseInfo, []byte) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), method, f.server.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", f.server.URL)
	request.AddCookie(&http.Cookie{
		Name:  "__Host-relay_access",
		Value: session.access,
	})
	request.AddCookie(&http.Cookie{
		Name:  "__Host-relay_csrf",
		Value: csrf,
	})
	if method == http.MethodDelete {
		request.Header.Set("X-CSRF-Token", csrf)
	}

	client := *f.client
	client.Jar = nil
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("management response can be cached")
	}
	return responseInfo{
		status:  response.StatusCode,
		header:  response.Header,
		cookies: response.Cookies(),
	}, body
}

type sessionPage struct {
	Sessions []struct {
		ID      string `json:"session_id"`
		Current bool   `json:"is_current"`
	} `json:"sessions"`
	Next string `json:"next_cursor"`
}

func (f *fixture) listSessions(
	t *testing.T,
	path string,
	session browserSession,
) sessionPage {
	t.Helper()
	response, body := f.managementRequest(t, http.MethodGet, path, session, session.csrf)
	if response.status != 200 || len(response.cookies) != 0 {
		t.Fatalf("session list status=%d", response.status)
	}
	for _, value := range []string{session.access, session.refresh, session.csrf, "csrf_hash", "token_hash"} {
		if strings.Contains(string(body), value) {
			t.Fatal("list exposed credentials")
		}
	}
	var page sessionPage
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatal(err)
	}
	return page
}

func TestSessionManagementThroughHTTPS(t *testing.T) {
	f := newFixture(t, false)
	email := uuid.NewV7().String() + "@example.com"

	f.registerVerified(t, email, managementPassword)
	older := f.loginSession(t, email)
	current := f.loginSession(t, email)
	foreignEmail := uuid.NewV7().String() + "@example.com"
	f.registerVerified(t, foreignEmail, managementPassword)
	foreign := f.loginSession(t, foreignEmail)
	first := f.listSessions(t, "/api/v1/auth/sessions?limit=1", current)
	if len(first.Sessions) != 1 ||
		first.Sessions[0].ID != current.id.String() ||
		!first.Sessions[0].Current ||
		first.Next == "" {
		t.Fatal("incorrect first page or current marker")
	}
	second := f.listSessions(t, "/api/v1/auth/sessions?limit=1&cursor="+url.QueryEscape(first.Next), current)
	if len(second.Sessions) != 1 ||
		second.Sessions[0].ID != older.id.String() ||
		second.Sessions[0].Current ||
		second.Next != "" {
		t.Fatal("incorrect terminal page")
	}
	for _, tc := range []struct {
		name   string
		path   string
		csrf   string
		status int
		code   string
	}{
		{
			name:   "foreign session",
			path:   "/api/v1/auth/sessions/" + foreign.id.String(),
			csrf:   current.csrf,
			status: 404,
			code:   "SESSION_NOT_FOUND",
		},
		{
			name:   "missing session",
			path:   "/api/v1/auth/sessions/" + uuid.NewV7().String(),
			csrf:   current.csrf,
			status: 404,
			code:   "SESSION_NOT_FOUND",
		},
		{
			name:   "other session CSRF",
			path:   "/api/v1/auth/sessions/" + older.id.String(),
			csrf:   older.csrf,
			status: 403,
			code:   "FORBIDDEN",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response, body := f.managementRequest(t, http.MethodDelete, tc.path, current, tc.csrf)
			if response.status != tc.status || len(response.cookies) != 0 {
				t.Fatalf("status=%d", response.status)
			}
			var problem struct {
				Code string `json:"code"`
			}
			if err := json.Unmarshal(body, &problem); err != nil || problem.Code != tc.code {
				t.Fatalf("problem: %s %v", body, err)
			}
		})
	}
	response, _ := f.managementRequest(
		t,
		http.MethodGet,
		"/api/v1/auth/sessions?cursor="+url.QueryEscape(first.Next),
		foreign,
		foreign.csrf,
	)
	if response.status != 400 || len(response.cookies) != 0 {
		t.Fatal("foreign cursor accepted")
	}
	for range 2 {
		selectedResponse, selectedBody := f.managementRequest(
			t,
			http.MethodDelete,
			"/api/v1/auth/sessions/"+older.id.String(),
			current,
			current.csrf,
		)
		if selectedResponse.status != 204 || len(selectedResponse.cookies) != 0 || len(selectedBody) != 0 {
			t.Fatalf("selected revoke status=%d", selectedResponse.status)
		}
	}
	response, _ = f.managementRequest(t, http.MethodGet, "/api/v1/auth/sessions", older, older.csrf)
	if response.status != 401 {
		t.Fatal("revoked access managed sessions")
	}
	page := f.listSessions(t, "/api/v1/auth/sessions", current)
	if len(page.Sessions) != 1 || page.Sessions[0].ID != current.id.String() {
		t.Fatal("revoked session remains in list")
	}
	response, body := f.managementRequest(t, http.MethodDelete, "/api/v1/auth/sessions", current, current.csrf)
	assertClearedSessionCookies(t, response, body)
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		response, _ = f.managementRequest(t, method, "/api/v1/auth/sessions", current, current.csrf)
		if response.status != 401 || len(response.cookies) != 0 {
			t.Fatal("revoke all caller remains active")
		}
	}
	if _, err := f.verifier.Verify(current.access); err != nil {
		t.Fatal("revoke all changed an issued JWT")
	}
	if page := f.listSessions(t, "/api/v1/auth/sessions", foreign); len(page.Sessions) != 1 {
		t.Fatal("revoke all affected another user")
	}
	next := f.loginSession(t, email)
	response, body = f.managementRequest(t, http.MethodDelete, "/api/v1/auth/sessions/"+next.id.String(), next, next.csrf)
	assertClearedSessionCookies(t, response, body)
}

func assertClearedSessionCookies(t *testing.T, response responseInfo, body []byte) {
	t.Helper()
	if response.status != 204 || len(response.cookies) != 3 || len(body) != 0 {
		t.Fatalf("self/all revoke status=%d cookies=%d", response.status, len(response.cookies))
	}
	for _, cookie := range response.cookies {
		path := "/"
		if cookie.Name == "__Secure-relay_refresh" {
			path = "/api/v1/auth"
		}
		if cookie.Value != "" || cookie.MaxAge != -1 || cookie.Path != path || !cookie.Secure || cookie.Domain != "" {
			t.Fatal("incorrect clearing cookie scope")
		}
	}
}
