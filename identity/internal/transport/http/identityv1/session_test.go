package identityv1

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/platform/pkg/security/accessjwt"

	"github.com/horizoonn/relay/identity/internal/domain"
	"github.com/horizoonn/relay/identity/internal/usecase/session"
)

func TestGetCurrentSessionHTTP(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := accessjwt.NewIssuer("test", private)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := accessjwt.NewVerifier(map[string]ed25519.PublicKey{"test": public})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	user, err := domain.NewUser("user@example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	current, err := domain.NewSession(user.ID, [32]byte{1}, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	token, err := issuer.Issue(user.ID, current.ID, current.CSRFHash, current.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		cookie     string
		usecaseErr error
		status     int
		code       string
		called     bool
	}{
		{
			name:       "valid",
			cookie:     accessCookieName + "=" + token.Raw,
			usecaseErr: nil,
			status:     200,
			code:       "",
			called:     true,
		},
		{
			name:       "missing",
			cookie:     "",
			usecaseErr: nil,
			status:     401,
			code:       "UNAUTHENTICATED",
			called:     false,
		},
		{
			name:       "malformed",
			cookie:     accessCookieName + "=invalid",
			usecaseErr: nil,
			status:     401,
			code:       "UNAUTHENTICATED",
			called:     false,
		},
		{
			name:       "empty",
			cookie:     accessCookieName + "=",
			usecaseErr: nil,
			status:     401,
			code:       "UNAUTHENTICATED",
			called:     false,
		},
		{
			name:       "duplicate",
			cookie:     accessCookieName + "=" + token.Raw + "; " + accessCookieName + "=" + token.Raw,
			usecaseErr: nil,
			status:     400,
			code:       "INVALID_REQUEST",
			called:     false,
		},
		{
			name:       "inactive",
			cookie:     accessCookieName + "=" + token.Raw,
			usecaseErr: session.ErrUnauthenticated,
			status:     401,
			code:       "UNAUTHENTICATED",
			called:     true,
		},
		{
			name:       "storage failure",
			cookie:     accessCookieName + "=" + token.Raw,
			usecaseErr: errors.New("sensitive database detail"),
			status:     500,
			code:       "INTERNAL_ERROR",
			called:     true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			service := fakeSessions{
				current: func(_ context.Context, u, s uuid.UUID) (session.Current, error) {
					called = true
					if u != user.ID || s != current.ID {
						t.Fatal("unverified IDs reached use case")
					}
					return session.Current{
						User:    user,
						Session: current,
					}, tc.usecaseErr
				},
			}
			var logs bytes.Buffer
			handler, newErr := NewHandler(
				fakeAuth{},
				service,
				verifier,
				testCursors(t),
				testLogger(&logs),
				unlimitedLimiter{},
				fakeAccounts{},
				fakeAccounts{},
			)
			if newErr != nil {
				t.Fatal(newErr)
			}
			server, newErr := NewServer(handler, testOrigin, nil)
			if newErr != nil {
				t.Fatal(newErr)
			}
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/auth/session", nil)
			if tc.cookie != "" {
				request.Header.Set("Cookie", tc.cookie)
			}

			response := httptest.NewRecorder()
			server.ServeHTTP(response, request)
			if response.Code != tc.status || called != tc.called {
				t.Fatalf("status=%d called=%t", response.Code, called)
			}
			assertPrivateResponse(t, response)
			if len(response.Header().Values("Set-Cookie")) != 0 {
				t.Fatal("GET changed cookies")
			}
			if tc.status != 200 {
				assertProblem(t, response, tc.status, tc.code)
			} else {
				var fields map[string]any
				if decodeErr := json.Unmarshal(response.Body.Bytes(), &fields); decodeErr != nil {
					t.Fatal(decodeErr)
				}

				if fields["user_id"] != user.ID.String() || fields["session_id"] != current.ID.String() ||
					fields["email"] != user.Email || fields["email_verified"] != false || len(fields) != 7 {
					t.Fatal("incorrect session representation")
				}
				for name, want := range map[string]time.Time{
					"access_expires_at":  token.ExpiresAt,
					"session_expires_at": current.ExpiresAt,
					"authenticated_at":   current.AuthenticatedAt,
				} {
					value, ok := fields[name].(string)
					parsed, parseErr := time.Parse(time.RFC3339, value)
					if !ok || parseErr != nil || !parsed.Equal(want) {
						t.Fatal("GET changed expiry or authentication time")
					}
				}
			}
			for _, output := range []string{response.Body.String(), logs.String()} {
				if strings.Contains(output, token.Raw) ||
					strings.Contains(output, "sensitive database detail") ||
					strings.Contains(output, "csrf_hash") {
					t.Fatal("credential or private details exposed")
				}
			}
		})
	}
}
