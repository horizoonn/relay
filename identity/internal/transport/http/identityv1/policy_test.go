package identityv1

import (
	"net/http"
	"net/http/httptest"
	"testing"

	identitylimit "github.com/horizoonn/relay/identity/internal/ratelimit"
)

func TestOperationPolicy(t *testing.T) {
	for _, tc := range []struct {
		method  string
		path    string
		scope   identitylimit.Scope
		browser browserPolicy
	}{
		{
			method:  http.MethodPost,
			path:    "/api/v1/auth/register",
			scope:   identitylimit.RegisterIP,
			browser: browserJSON,
		},
		{
			method:  http.MethodPost,
			path:    "/api/v1/auth/login",
			scope:   identitylimit.LoginIP,
			browser: browserJSON,
		},
		{
			method:  http.MethodPost,
			path:    "/api/v1/auth/refresh",
			scope:   identitylimit.RefreshIP,
			browser: browserSession,
		},
		{
			method:  http.MethodPost,
			path:    "/api/v1/auth/email/verification-requests",
			scope:   identitylimit.EmailIP,
			browser: browserJSON,
		},
		{
			method:  http.MethodPost,
			path:    "/api/v1/auth/password/reset-requests",
			scope:   identitylimit.EmailIP,
			browser: browserJSON,
		},
		{
			method:  http.MethodPost,
			path:    "/api/v1/auth/email/verification",
			scope:   identitylimit.ActionIP,
			browser: browserJSON,
		},
		{
			method:  http.MethodPost,
			path:    "/api/v1/auth/password/reset",
			scope:   identitylimit.ActionIP,
			browser: browserJSON,
		},
		{
			method:  http.MethodDelete,
			path:    "/api/v1/auth/session",
			scope:   identitylimit.LogoutIP,
			browser: browserSession,
		},
		{
			method:  http.MethodDelete,
			path:    "/api/v1/auth/sessions",
			scope:   "",
			browser: browserManagement,
		},
		{
			method:  http.MethodDelete,
			path:    "/api/v1/auth/sessions/example",
			scope:   "",
			browser: browserManagement,
		},
		{
			method:  http.MethodGet,
			path:    "/api/v1/auth/session",
			scope:   "",
			browser: browserRead,
		},
		{
			method:  http.MethodGet,
			path:    "/api/v1/auth/sessions",
			scope:   "",
			browser: browserRead,
		},
		{
			method:  http.MethodPost,
			path:    "/unknown",
			scope:   "",
			browser: browserNone,
		},
		{
			method:  http.MethodPatch,
			path:    "/api/v1/auth/login",
			scope:   "",
			browser: browserNone,
		},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			request := httptest.NewRequestWithContext(t.Context(), tc.method, tc.path, nil)
			policy := policyFor(request)
			if policy.scope != tc.scope || policy.browser != tc.browser {
				t.Fatalf("policy=%+v", policy)
			}
		})
	}
}
