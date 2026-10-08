package identityv1

import (
	"net/http"
	"strings"

	identitylimit "github.com/horizoonn/relay/identity/internal/ratelimit"
)

type browserPolicy uint8

const (
	browserNone browserPolicy = iota
	browserJSON
	browserSession
	browserManagement
	browserRead
)

type operationPolicy struct {
	scope   identitylimit.Scope
	browser browserPolicy
}

func policyFor(r *http.Request) operationPolicy {
	switch r.Method {
	case http.MethodPost:
		switch r.URL.Path {
		case "/api/v1/auth/register":
			return operationPolicy{
				scope:   identitylimit.RegisterIP,
				browser: browserJSON,
			}
		case "/api/v1/auth/login":
			return operationPolicy{
				scope:   identitylimit.LoginIP,
				browser: browserJSON,
			}
		case "/api/v1/auth/refresh":
			return operationPolicy{
				scope:   identitylimit.RefreshIP,
				browser: browserSession,
			}
		case "/api/v1/auth/email/verification-requests", "/api/v1/auth/password/reset-requests":
			return operationPolicy{
				scope:   identitylimit.EmailIP,
				browser: browserJSON,
			}
		case "/api/v1/auth/email/verification", "/api/v1/auth/password/reset":
			return operationPolicy{
				scope:   identitylimit.ActionIP,
				browser: browserJSON,
			}
		}
	case http.MethodDelete:
		if r.URL.Path == "/api/v1/auth/session" {
			return operationPolicy{
				scope:   identitylimit.LogoutIP,
				browser: browserSession,
			}
		}
		if r.URL.Path == "/api/v1/auth/sessions" || strings.HasPrefix(r.URL.Path, "/api/v1/auth/sessions/") {
			return operationPolicy{
				browser: browserManagement,
			}
		}
	case http.MethodGet:
		if r.URL.Path == "/api/v1/auth/session" || r.URL.Path == "/api/v1/auth/sessions" {
			return operationPolicy{
				browser: browserRead,
			}
		}
	}
	return operationPolicy{}
}
