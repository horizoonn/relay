package identityv1

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"uuid"

	"github.com/horizoonn/relay/platform/pkg/security/accessjwt"
	"go.uber.org/zap"

	"github.com/horizoonn/relay/identity/internal/usecase/session"
)

type managementVerifier struct {
	userID    uuid.UUID
	sessionID uuid.UUID
}

func (v managementVerifier) Verify(raw string) (accessjwt.Access, error) {
	if raw != "test-access" {
		return accessjwt.Access{}, accessjwt.ErrInvalidToken
	}
	return accessjwt.Access{
		UserID:    v.userID,
		SessionID: v.sessionID,
	}, nil
}

func TestSessionManagementErrors(t *testing.T) {
	t.Parallel()
	userID, callerID, targetID := uuid.NewV7(), uuid.NewV7(), uuid.NewV7()
	for _, path := range []string{"/api/v1/auth/sessions", "/api/v1/auth/sessions/" + targetID.String()} {
		for _, tc := range []struct {
			name       string
			edit       func(*http.Request)
			serviceErr error
			status     int
			code       string
			called     bool
		}{
			{
				name: "other or all sessions",
				edit: func(*http.Request) {
				},
				serviceErr: nil,
				status:     204,
				code:       "",
				called:     true,
			},
			{
				name: "missing origin",
				edit: func(r *http.Request) {
					r.Header.Del("Origin")
				},
				serviceErr: nil,
				status:     403,
				code:       "FORBIDDEN",
				called:     false,
			},
			{
				name: "foreign origin",
				edit: func(r *http.Request) {
					r.Header.Set("Origin", "https://other.example")
				},
				serviceErr: nil,
				status:     403,
				code:       "FORBIDDEN",
				called:     false,
			},
			{
				name: "duplicate origin",
				edit: func(r *http.Request) {
					r.Header.Add("Origin", testOrigin)
				},
				serviceErr: nil,
				status:     403,
				code:       "FORBIDDEN",
				called:     false,
			},
			{
				name: "missing CSRF header",
				edit: func(r *http.Request) {
					r.Header.Del("X-CSRF-Token")
				},
				serviceErr: nil,
				status:     403,
				code:       "FORBIDDEN",
				called:     false,
			},
			{
				name: "duplicate CSRF header",
				edit: func(r *http.Request) {
					r.Header.Add("X-CSRF-Token", "test-csrf")
				},
				serviceErr: nil,
				status:     403,
				code:       "FORBIDDEN",
				called:     false,
			},
			{
				name: "wrong CSRF header",
				edit: func(r *http.Request) {
					r.Header.Set("X-CSRF-Token", "other-csrf")
				},
				serviceErr: nil,
				status:     403,
				code:       "FORBIDDEN",
				called:     false,
			},
			{
				name: "duplicate cookie",
				edit: func(r *http.Request) {
					r.Header.Add("Cookie", csrfCookieName+"=test-csrf")
				},
				serviceErr: nil,
				status:     400,
				code:       "INVALID_REQUEST",
				called:     false,
			},
			{
				name: "missing access",
				edit: func(r *http.Request) {
					r.Header.Set("Cookie", csrfCookieName+"=test-csrf")
				},
				serviceErr: nil,
				status:     401,
				code:       "UNAUTHENTICATED",
				called:     false,
			},
			{
				name: "body",
				edit: func(r *http.Request) {
					r.ContentLength = 2
				},
				serviceErr: nil,
				status:     400,
				code:       "INVALID_REQUEST",
				called:     false,
			},
			{
				name: "stored CSRF mismatch",
				edit: func(*http.Request) {
				},
				serviceErr: session.ErrCSRF,
				status:     403,
				code:       "FORBIDDEN",
				called:     true,
			},
			{
				name: "revoked caller",
				edit: func(*http.Request) {
				},
				serviceErr: session.ErrUnauthenticated,
				status:     401,
				code:       "UNAUTHENTICATED",
				called:     true,
			},
			{
				name: "database failure",
				edit: func(*http.Request) {
				},
				serviceErr: errors.New("private database detail"),
				status:     500,
				code:       "INTERNAL_ERROR",
				called:     true,
			},
		} {
			t.Run(path+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				called := false
				check := func(u, caller uuid.UUID, csrf string) error {
					called = true
					if u != userID || caller != callerID || csrf != "test-csrf" {
						t.Fatal("incorrect management principal or CSRF")
					}
					return tc.serviceErr
				}
				svc := fakeSessions{
					revoke: func(_ context.Context, u, caller, target uuid.UUID, csrf string) error {
						if target != targetID {
							t.Fatal("incorrect target")
						}
						return check(u, caller, csrf)
					},
					revokeAll: func(_ context.Context, u, caller uuid.UUID, csrf string) error { return check(u, caller, csrf) },
				}
				handler, err := NewHandler(fakeAuth{}, svc, managementVerifier{
					userID,
					callerID,
				}, testCursors(t), zap.NewNop(), unlimitedLimiter{}, fakeAccounts{}, fakeAccounts{})
				if err != nil {
					t.Fatal(err)
				}
				server, err := NewServer(handler, testOrigin, nil)
				if err != nil {
					t.Fatal(err)
				}
				request := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, path, nil)
				request.Header.Set("Origin", testOrigin)
				request.Header.Set("Cookie", accessCookieName+"=test-access; "+csrfCookieName+"=test-csrf")
				request.Header.Set("X-CSRF-Token", "test-csrf")
				tc.edit(request)
				response := httptest.NewRecorder()
				server.ServeHTTP(response, request)
				if response.Code != tc.status || called != tc.called {
					t.Fatalf("status=%d called=%t", response.Code, called)
				}
				if tc.status >= 400 {
					assertProblem(t, response, tc.status, tc.code)
				} else {
					expected := 0
					if path == "/api/v1/auth/sessions" {
						expected = 3
					}
					if len(response.Header().Values("Set-Cookie")) != expected || response.Body.Len() != 0 {
						t.Fatal("incorrect mutation response")
					}
					assertPrivateResponse(t, response)
				}
				if strings.Contains(response.Body.String(), "private database detail") {
					t.Fatal("database details exposed")
				}
			})
		}
	}
}

func TestListSessionsQuery(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		query string
	}{
		{
			name:  "zero limit",
			query: "limit=0",
		},
		{
			name:  "negative limit",
			query: "limit=-1",
		},
		{
			name:  "limit above maximum",
			query: "limit=101",
		},
		{
			name:  "noninteger limit",
			query: "limit=one",
		},
		{
			name:  "empty cursor",
			query: "cursor=",
		},
		{
			name:  "unsigned cursor",
			query: "cursor=modified",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			called := false
			svc := fakeSessions{
				list: func(context.Context, uuid.UUID, uuid.UUID, session.ListParams) (session.Page, error) {
					called = true
					return session.Page{}, nil
				},
			}
			handler, err := NewHandler(fakeAuth{}, svc, managementVerifier{
				uuid.NewV7(),
				uuid.NewV7(),
			}, testCursors(t), zap.NewNop(), unlimitedLimiter{}, fakeAccounts{}, fakeAccounts{})
			if err != nil {
				t.Fatal(err)
			}
			server, err := NewServer(handler, testOrigin, nil)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/auth/sessions?"+tc.query, nil)
			request.AddCookie(&http.Cookie{
				Name:  accessCookieName,
				Value: "test-access",
			})
			response := httptest.NewRecorder()
			server.ServeHTTP(response, request)
			assertProblem(t, response, 400, "INVALID_REQUEST")
			if called {
				t.Fatal("invalid query reached use case")
			}
		})
	}
}
