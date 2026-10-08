package contentv1

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/golang-jwt/jwt/v5"
	"github.com/horizoonn/relay/platform/pkg/security/accessjwt"
)

func TestLocalJWTAndSessionBoundCSRF(t *testing.T) {
	t.Parallel()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	oldPublic, oldPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := accessjwt.NewVerifier(map[string]ed25519.PublicKey{
		"current": public, "previous": oldPublic,
	})
	if err != nil {
		t.Fatal(err)
	}
	owner, session := uuid.NewV7(), uuid.NewV7()
	csrf := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	csrfHash := sha256.Sum256([]byte(csrf))
	issue := func(id string, key ed25519.PrivateKey) string {
		t.Helper()
		issuer, issueErr := accessjwt.NewIssuer(id, key)
		if issueErr != nil {
			t.Fatal(issueErr)
		}
		token, issueErr := issuer.Issue(owner, session, csrfHash, time.Now().Add(time.Hour))
		if issueErr != nil {
			t.Fatal(issueErr)
		}
		return token.Raw
	}
	current, previous := issue("current", private), issue("previous", oldPrivate)
	unknown := issue("unknown", private)
	wrongSignature := issue("current", oldPrivate)
	expired := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": "relay-identity", "aud": "relay-api", "sub": owner.String(), "sid": session.String(),
		"iat": time.Now().Add(-10 * time.Minute).Unix(), "exp": time.Now().Add(-5 * time.Minute).Unix(),
		"csrf_hash": base64.RawURLEncoding.EncodeToString(csrfHash[:]),
	})
	expired.Header["typ"], expired.Header["kid"] = "relay-at+jwt", "current"
	expiredRaw, err := expired.SignedString(private)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name     string
		raw      string
		mutation bool
		edit     func(*http.Request)
		want     int
		code     string
	}{
		{
			name: "valid JWT GET",
			raw:  current,
			want: 200,
		},
		{
			name: "previous key GET",
			raw:  previous,
			want: 200,
		},
		{
			name:     "signed Capture",
			raw:      current,
			mutation: true,
			want:     201,
		},
		{
			name: "missing access",
			want: 401,
			code: "UNAUTHENTICATED",
		},
		{
			name: "invalid JWT",
			raw:  "invalid",
			want: 401,
			code: "UNAUTHENTICATED",
		},
		{
			name: "expired JWT",
			raw:  expiredRaw,
			want: 401,
			code: "UNAUTHENTICATED",
		},
		{
			name: "unknown signing key",
			raw:  unknown,
			want: 401,
			code: "UNAUTHENTICATED",
		},
		{
			name: "wrong signature",
			raw:  wrongSignature,
			want: 401,
			code: "UNAUTHENTICATED",
		},
		{
			name: "duplicate access",
			raw:  current,
			edit: func(r *http.Request) {
				r.AddCookie(&http.Cookie{
					Name:  "__Host-relay_access",
					Value: current,
				})
			},
			want: 400,
			code: "INVALID_REQUEST",
		},
		{
			name:     "missing CSRF cookie",
			raw:      current,
			mutation: true,
			edit: func(r *http.Request) {
				r.Header.Set("Cookie", "__Host-relay_access="+current)
			},
			want: 403,
			code: "FORBIDDEN",
		},
		{
			name:     "wrong CSRF cookie",
			raw:      current,
			mutation: true,
			edit: func(r *http.Request) {
				r.Header.Set("Cookie", "__Host-relay_access="+current+"; __Host-relay_csrf=wrong")
			},
			want: 403,
			code: "FORBIDDEN",
		},
		{
			name:     "wrong session CSRF",
			raw:      current,
			mutation: true,
			edit: func(r *http.Request) {
				r.Header.Set("Cookie", "__Host-relay_access="+current+"; __Host-relay_csrf="+testCSRF)
				r.Header.Set("X-CSRF-Token", testCSRF)
			},
			want: 403,
			code: "FORBIDDEN",
		},
		{
			name:     "missing CSRF header",
			raw:      current,
			mutation: true,
			edit: func(r *http.Request) {
				r.Header.Del("X-CSRF-Token")
			},
			want: 403,
			code: "FORBIDDEN",
		},
		{
			name:     "duplicate CSRF cookie",
			raw:      current,
			mutation: true,
			edit: func(r *http.Request) {
				r.AddCookie(&http.Cookie{
					Name:  "__Host-relay_csrf",
					Value: csrf,
				})
			},
			want: 400,
			code: "INVALID_REQUEST",
		},
		{
			name:     "missing Origin",
			raw:      current,
			mutation: true,
			edit: func(r *http.Request) {
				r.Header.Del("Origin")
			},
			want: 403,
			code: "FORBIDDEN",
		},
		{
			name:     "foreign Origin",
			raw:      current,
			mutation: true,
			edit: func(r *http.Request) {
				r.Header.Set("Origin", "https://evil.example")
			},
			want: 403,
			code: "FORBIDDEN",
		},
		{
			name:     "duplicate Origin",
			raw:      current,
			mutation: true,
			edit: func(r *http.Request) {
				r.Header.Add("Origin", testOrigin)
			},
			want: 403,
			code: "FORBIDDEN",
		},
		{
			name:     "duplicate CSRF header",
			raw:      current,
			mutation: true,
			edit: func(r *http.Request) {
				r.Header.Add("X-CSRF-Token", csrf)
			},
			want: 403,
			code: "FORBIDDEN",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			server, err := NewServer(testHandler(t), verifier, testOrigin, unlimitedLimiter{})
			if err != nil {
				t.Fatal(err)
			}
			method, path, body := http.MethodGet, "/api/v1/items/recent", ""
			if tc.mutation {
				method, path, body = http.MethodPost, "/api/v1/items", `{"source_type":"text","text":"JWT Capture"}`
			}
			r := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
			if tc.raw != "" {
				r.AddCookie(&http.Cookie{
					Name:  "__Host-relay_access",
					Value: tc.raw,
				})
			}
			if tc.mutation {
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Idempotency-Key", "signed-capture")
				r.Header.Set("X-CSRF-Token", csrf)
				r.Header.Set("Origin", testOrigin)
				r.AddCookie(&http.Cookie{
					Name:  "__Host-relay_csrf",
					Value: csrf,
				})
			}
			if tc.edit != nil {
				tc.edit(r)
			}
			w := httptest.NewRecorder()
			server.ServeHTTP(w, r)
			if tc.code != "" {
				assertProblem(t, w, tc.want, tc.code)
			} else if w.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.want, w.Body.String())
			}
		})
	}
}
