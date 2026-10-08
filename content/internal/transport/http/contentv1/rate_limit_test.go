package contentv1

import (
	"context"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/platform/pkg/ratelimit"
	contentapi "github.com/horizoonn/relay/shared/pkg/openapi/content/v1"

	contentlimit "github.com/horizoonn/relay/content/internal/ratelimit"
)

type unlimitedLimiter struct{}

func (unlimitedLimiter) Allow(context.Context, contentlimit.Scope, string) error { return nil }

type limiterFunc func(context.Context, contentlimit.Scope, string) error

func (f limiterFunc) Allow(ctx context.Context, scope contentlimit.Scope, subject string) error {
	return f(ctx, scope, subject)
}

func TestContentRouteRateLimits(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		path   string
		body   string
		media  string
		scope  contentlimit.Scope
	}{
		{
			name:   "capture",
			method: http.MethodPost,
			path:   "/api/v1/items",
			body:   `{"source_type":"text","text":"content"}`,
			media:  "application/json",
			scope:  contentlimit.Capture,
		},
		{
			name:   "patch",
			method: http.MethodPatch,
			path:   "/api/v1/items/00000000-0000-0000-0000-000000000002",
			body:   `{"keep":true}`,
			media:  "application/merge-patch+json",
			scope:  contentlimit.Write,
		},
		{
			name:   "delete",
			method: http.MethodDelete,
			path:   "/api/v1/items/00000000-0000-0000-0000-000000000002",
			body:   "",
			media:  "",
			scope:  contentlimit.Write,
		},
		{
			name:   "get",
			method: http.MethodGet,
			path:   "/api/v1/items/00000000-0000-0000-0000-000000000002",
			body:   "",
			media:  "",
			scope:  contentlimit.Read,
		},
		{
			name:   "recent",
			method: http.MethodGet,
			path:   "/api/v1/items/recent",
			body:   "",
			media:  "",
			scope:  contentlimit.Read,
		},
		{
			name:   "library",
			method: http.MethodGet,
			path:   "/api/v1/items/library",
			body:   "",
			media:  "",
			scope:  contentlimit.Read,
		},
		{
			name:   "later",
			method: http.MethodGet,
			path:   "/api/v1/items/later",
			body:   "",
			media:  "",
			scope:  contentlimit.Read,
		},
		{
			name:   "search",
			method: http.MethodGet,
			path:   "/api/v1/items/search?q=content",
			body:   "",
			media:  "",
			scope:  contentlimit.Search,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			limiter := limiterFunc(func(_ context.Context, scope contentlimit.Scope, subject string) error {
				calls++
				if scope != tc.scope || subject != routeOwnerID.String() {
					t.Fatalf("scope=%s subject=%s", scope, subject)
				}
				return &ratelimit.ExceededError{
					RetryAfter: 1500 * time.Millisecond,
				}
			})
			server, err := NewServer(testHandler(t), fakeVerifier{
				owner: routeOwnerID,
				csrf:  testCSRF,
			}, testOrigin, limiter)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequestWithContext(t.Context(), tc.method, tc.path, strings.NewReader(tc.body))
			req.AddCookie(&http.Cookie{
				Name:  "__Host-relay_access",
				Value: "access",
			})
			req.Header.Set("Idempotency-Key", "rate-test")
			if tc.media != "" {
				req.Header.Set("Content-Type", tc.media)
			}
			if tc.method != http.MethodGet {
				req.Header.Set("Origin", testOrigin)
				req.Header.Set("X-CSRF-Token", testCSRF)
				req.AddCookie(&http.Cookie{
					Name:  "__Host-relay_csrf",
					Value: testCSRF,
				})
			}
			response := httptest.NewRecorder()
			server.ServeHTTP(response, req)
			var problem contentapi.Problem
			if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
				t.Fatal(err)
			}
			if calls != 1 ||
				response.Code != 429 ||
				response.Header().Get("Retry-After") != "2" ||
				problem.Status != 429 ||
				problem.Code != contentapi.ProblemCodeTOOMANYREQUESTS ||
				len(response.Header().Values("Set-Cookie")) != 0 {
				t.Fatalf("calls=%d status=%d header=%v body=%s", calls, response.Code, response.Header(), response.Body)
			}
		})
	}
}

func TestRateLimitAdmission(t *testing.T) {
	for _, tc := range []struct {
		name         string
		invalidToken bool
		validCSRF    bool
		status       int
	}{
		{
			name:         "invalid access",
			invalidToken: true,
			validCSRF:    true,
			status:       401,
		}, {
			name:         "invalid CSRF",
			invalidToken: false,
			validCSRF:    false,
			status:       403,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			verifier := fakeVerifier{
				owner: uuid.NewV7(),
				csrf:  testCSRF,
			}
			if tc.invalidToken {
				verifier.err = errUnauthenticated
			}
			server, err := NewServer(
				testHandler(t),
				verifier,
				testOrigin,
				limiterFunc(func(
					context.Context,
					contentlimit.Scope,
					string,
				) error {
					calls++
					return nil
				}),
			)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequestWithContext(
				t.Context(),
				http.MethodDelete,
				"/api/v1/items/00000000-0000-0000-0000-000000000002",
				nil,
			)
			req.AddCookie(&http.Cookie{
				Name:  "__Host-relay_access",
				Value: "access",
			})
			req.Header.Set("Origin", testOrigin)
			req.Header.Set("X-CSRF-Token", testCSRF)
			if tc.validCSRF {
				req.AddCookie(&http.Cookie{
					Name:  "__Host-relay_csrf",
					Value: testCSRF,
				})
			}
			response := httptest.NewRecorder()
			server.ServeHTTP(response, req)
			if response.Code != tc.status || calls != 0 {
				t.Fatalf("status=%d calls=%d", response.Code, calls)
			}
		})
	}
}

func TestUnknownContentOperationHasNoRatePolicy(t *testing.T) {
	if _, err := rateLimitScope("future-operation"); err == nil {
		t.Fatal("unknown operation admitted without policy")
	}
	if _, err := NewServer(testHandler(t), fakeVerifier{}, testOrigin, nil); err == nil {
		t.Fatal("nil limiter accepted")
	}
}
