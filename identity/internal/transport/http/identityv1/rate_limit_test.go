package identityv1

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/platform/pkg/ratelimit"
	identityapi "github.com/horizoonn/relay/shared/pkg/openapi/identity/v1"
	"go.uber.org/zap"

	"github.com/horizoonn/relay/identity/internal/password"
	identitylimit "github.com/horizoonn/relay/identity/internal/ratelimit"
)

func TestClientIP(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("172.31.254.0/28")}
	for _, tc := range []struct {
		name      string
		peer      string
		forwarded []string
		want      string
		invalid   bool
	}{
		{
			name:      "direct IPv4",
			peer:      "192.0.2.4:1234",
			forwarded: nil,
			want:      "192.0.2.4",
			invalid:   false,
		},
		{
			name:      "untrusted spoof",
			peer:      "192.0.2.4:1234",
			forwarded: []string{"198.51.100.8"},
			want:      "192.0.2.4",
			invalid:   false,
		},
		{
			name:      "trusted proxy",
			peer:      "172.31.254.2:1234",
			forwarded: []string{"198.51.100.8"},
			want:      "198.51.100.8",
			invalid:   false,
		},
		{
			name:      "mapped IPv4",
			peer:      "[::ffff:192.0.2.4]:1234",
			forwarded: nil,
			want:      "192.0.2.4",
			invalid:   false,
		},
		{
			name:      "IPv6 network",
			peer:      "[2001:db8:1::abcd]:1234",
			forwarded: nil,
			want:      "2001:db8:1::/64",
			invalid:   false,
		},
		{
			name:      "missing forwarded address",
			peer:      "172.31.254.2:1234",
			forwarded: nil,
			want:      "",
			invalid:   true,
		},
		{
			name:      "forwarded chain",
			peer:      "172.31.254.2:1234",
			forwarded: []string{"198.51.100.8, 203.0.113.9"},
			want:      "",
			invalid:   true,
		},
		{
			name:      "duplicate forwarded address",
			peer:      "172.31.254.2:1234",
			forwarded: []string{"198.51.100.8", "203.0.113.9"},
			want:      "",
			invalid:   true,
		},
		{
			name:      "forwarded zone",
			peer:      "172.31.254.2:1234",
			forwarded: []string{"fe80::1%eth0"},
			want:      "",
			invalid:   true,
		},
		{
			name:      "invalid peer",
			peer:      "invalid",
			forwarded: nil,
			want:      "",
			invalid:   true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", nil)
			r.RemoteAddr = tc.peer
			for _, value := range tc.forwarded {
				r.Header.Add("X-Forwarded-For", value)
			}
			got, err := clientIP(r, trusted)
			if (err != nil) != tc.invalid || got != tc.want {
				t.Fatalf("got=%q err=%v", got, err)
			}
		})
	}
}

type limiterFunc func(context.Context, identitylimit.Scope, string) error

func (f limiterFunc) Allow(ctx context.Context, scope identitylimit.Scope, subject string) error {
	return f(ctx, scope, subject)
}

func TestPublicRouteRateLimits(t *testing.T) {
	for _, tc := range []struct {
		name  string
		path  string
		scope identitylimit.Scope
	}{
		{
			name:  "login",
			path:  "/api/v1/auth/login",
			scope: identitylimit.LoginIP,
		},
		{
			name:  "verification request",
			path:  "/api/v1/auth/email/verification-requests",
			scope: identitylimit.EmailIP,
		},
		{
			name:  "reset request",
			path:  "/api/v1/auth/password/reset-requests",
			scope: identitylimit.EmailIP,
		},
		{
			name:  "verification",
			path:  "/api/v1/auth/email/verification",
			scope: identitylimit.ActionIP,
		},
		{
			name:  "password reset",
			path:  "/api/v1/auth/password/reset",
			scope: identitylimit.ActionIP,
		},
		{
			name:  "register",
			path:  "/api/v1/auth/register",
			scope: identitylimit.RegisterIP,
		},
		{
			name:  "refresh",
			path:  "/api/v1/auth/refresh",
			scope: identitylimit.RefreshIP,
		},
		{
			name:  "logout",
			path:  "/api/v1/auth/session",
			scope: identitylimit.LogoutIP,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, err := NewHandler(
				fakeAuth{},
				fakeSessions{},
				rejectingVerifier{},
				testCursors(t),
				zap.NewNop(),
				limiterFunc(func(
					_ context.Context,
					scope identitylimit.Scope,
					subject string,
				) error {
					if scope != tc.scope || subject != "192.0.2.1" {
						t.Fatalf("scope=%s subject=%s", scope, subject)
					}
					return &ratelimit.ExceededError{
						RetryAfter: 1500 * time.Millisecond,
					}
				}),
				fakeAccounts{},
				fakeAccounts{},
			)
			if err != nil {
				t.Fatal(err)
			}
			method := http.MethodPost
			if tc.scope == identitylimit.LogoutIP {
				method = http.MethodDelete
			}
			r := httptest.NewRequestWithContext(t.Context(), method, tc.path, nil)
			called := false
			response := httptest.NewRecorder()
			h.limitRequests(
				http.HandlerFunc(func(
					http.ResponseWriter,
					*http.Request,
				) {
					called = true
				}),
				nil,
			).ServeHTTP(
				response,
				r,
			)
			if called ||
				response.Code != 429 ||
				response.Header().Get("Retry-After") != "2" ||
				len(response.Header().Values("Set-Cookie")) != 0 {
				t.Fatalf("status=%d header=%v called=%v", response.Code, response.Header(), called)
			}
		})
	}
}

func TestAuthenticatedRouteRateLimits(t *testing.T) {
	for _, tc := range []struct {
		name      string
		operation identityapi.OperationName
		scope     identitylimit.Scope
	}{
		{
			name:      "current",
			operation: identityapi.GetCurrentSessionOperation,
			scope:     identitylimit.ReadUser,
		},
		{
			name:      "list",
			operation: identityapi.ListSessionsOperation,
			scope:     identitylimit.ReadUser,
		},
		{
			name:      "selected revocation",
			operation: identityapi.RevokeSessionOperation,
			scope:     identitylimit.RevokeUser,
		},
		{
			name:      "all revocation",
			operation: identityapi.RevokeAllSessionsOperation,
			scope:     identitylimit.RevokeUser,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			owner, sessionID := uuid.NewV7(), uuid.NewV7()
			h := &Handler{
				verifier: managementVerifier{
					owner,
					sessionID,
				},
				limiter: limiterFunc(func(_ context.Context, scope identitylimit.Scope, subject string) error {
					if scope != tc.scope || subject != owner.String() {
						t.Fatalf("scope=%s subject=%s", scope, subject)
					}
					return &ratelimit.ExceededError{
						RetryAfter: time.Second,
					}
				}),
			}
			ctx, err := h.HandleAccessCookie(t.Context(), tc.operation, identityapi.AccessCookie{
				APIKey: "test-access",
			})
			var exceeded *ratelimit.ExceededError
			if ctx != nil || !errors.As(err, &exceeded) {
				t.Fatalf("ctx=%v err=%v", ctx, err)
			}
		})
	}
}

func TestRateLimitErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
		code   identityapi.ProblemCode
		retry  string
	}{
		{
			name: "rate exceeded",
			err: &ratelimit.ExceededError{
				RetryAfter: time.Millisecond,
			},
			status: 429,
			code:   identityapi.ProblemCodeRATELIMITED,
			retry:  "1",
		},
		{
			name:   "Redis unavailable",
			err:    ratelimit.ErrUnavailable,
			status: 503,
			code:   identityapi.ProblemCodeSERVICEUNAVAILABLE,
			retry:  "",
		},
		{
			name:   "password capacity",
			err:    password.ErrBusy,
			status: 503,
			code:   identityapi.ProblemCodeSERVICEUNAVAILABLE,
			retry:  "1",
		},
		{
			name: "wrapped rate exceeded",
			err: fmt.Errorf("limit account login: %w", &ratelimit.ExceededError{
				RetryAfter: 1500 * time.Millisecond,
			}),
			status: 429,
			code:   identityapi.ProblemCodeRATELIMITED,
			retry:  "2",
		},
		{
			name:   "wrapped Redis unavailable",
			err:    fmt.Errorf("limit account email request: %w", ratelimit.ErrUnavailable),
			status: 503,
			code:   identityapi.ProblemCodeSERVICEUNAVAILABLE,
			retry:  "",
		},
		{
			name:   "wrapped password capacity",
			err:    fmt.Errorf("hash registration password: %w", password.ErrBusy),
			status: 503,
			code:   identityapi.ProblemCodeSERVICEUNAVAILABLE,
			retry:  "1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{
				log: zap.NewNop(),
			}
			problem := h.NewError(t.Context(), tc.err)
			response := httptest.NewRecorder()
			h.writeProblem(response, problem)
			if response.Code != tc.status ||
				problem.Response.Status != tc.status ||
				problem.Response.Code != tc.code ||
				response.Header().Get("Retry-After") != tc.retry {
				t.Fatalf("problem=%v header=%v", problem, response.Header())
			}
		})
	}
}

var _ AccessVerifier = managementVerifier{}
