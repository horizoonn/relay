package identityv1

import (
	"crypto/subtle"
	"mime"
	"net/http"

	"github.com/horizoonn/relay/platform/pkg/httpmiddleware"
	identityapi "github.com/horizoonn/relay/shared/pkg/openapi/identity/v1"
)

const maxJSONBodyBytes = 4 << 10

func requestMiddleware(next http.Handler) http.Handler {
	limited := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
	return httpmiddleware.RequestIDs(httpmiddleware.PrivateResponses(limited))
}

func (h *Handler) browserRequests(next http.Handler, allowedOrigin string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if problem := validateBrowserOperation(r, allowedOrigin); problem != nil {
			h.writeProblem(w, problem)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func validateBrowserOperation(r *http.Request, origin string) *identityapi.ProblemStatusCodeWithHeaders {
	switch policyFor(r).browser {
	case browserJSON:
		return validateBrowserRequest(r, origin)
	case browserSession:
		return validateSessionMutation(r, origin)
	case browserManagement:
		return validateManagementMutation(r, origin)
	case browserRead:
		if duplicateAuthCookies(r) {
			return problemFor(r.Context(), http.StatusBadRequest, identityapi.ProblemCodeINVALIDREQUEST,
				"Invalid request", "Duplicate authentication cookies")
		}
	case browserNone:
	}
	return nil
}

func validateSessionMutation(r *http.Request, origin string) *identityapi.ProblemStatusCodeWithHeaders {
	if problem := validateMutationRequest(r, origin); problem != nil {
		return problem
	}
	refresh, err := r.Cookie(refreshCookieName)
	if err != nil || refresh.Value == "" {
		if r.Method == http.MethodDelete {
			return nil
		}
		return problemFor(r.Context(), http.StatusUnauthorized, identityapi.ProblemCodeUNAUTHENTICATED,
			"Unauthenticated", "Authentication required")
	}
	return validateCSRFCookies(r)
}

func validateManagementMutation(r *http.Request, origin string) *identityapi.ProblemStatusCodeWithHeaders {
	if problem := validateMutationRequest(r, origin); problem != nil {
		return problem
	}
	return validateCSRFCookies(r)
}

func validateMutationRequest(r *http.Request, origin string) *identityapi.ProblemStatusCodeWithHeaders {
	if len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != origin {
		return problemFor(r.Context(), http.StatusForbidden, identityapi.ProblemCodeFORBIDDEN,
			"Forbidden", "Request origin is not allowed")
	}
	if duplicateAuthCookies(r) {
		return problemFor(r.Context(), http.StatusBadRequest, identityapi.ProblemCodeINVALIDREQUEST,
			"Invalid request", "Duplicate authentication cookies")
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		return problemFor(r.Context(), http.StatusBadRequest, identityapi.ProblemCodeINVALIDREQUEST,
			"Invalid request", "This operation accepts no request body")
	}
	return nil
}

func validateCSRFCookies(r *http.Request) *identityapi.ProblemStatusCodeWithHeaders {
	csrf, err := r.Cookie(csrfCookieName)
	header := r.Header.Get("X-CSRF-Token")
	if err != nil || len(r.Header.Values("X-CSRF-Token")) != 1 || header == "" || len(header) > 128 ||
		subtle.ConstantTimeCompare([]byte(csrf.Value), []byte(header)) != 1 {
		return problemFor(r.Context(), http.StatusForbidden, identityapi.ProblemCodeFORBIDDEN,
			"Forbidden", "CSRF token is invalid")
	}
	return nil
}

func validateBrowserRequest(
	r *http.Request,
	allowedOrigin string,
) *identityapi.ProblemStatusCodeWithHeaders {
	if len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != allowedOrigin {
		return problemFor(r.Context(), http.StatusForbidden, identityapi.ProblemCodeFORBIDDEN,
			"Forbidden", "Request origin is not allowed")
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if len(r.Header.Values("Content-Type")) != 1 || err != nil || mediaType != "application/json" {
		return problemFor(r.Context(), http.StatusUnsupportedMediaType, identityapi.ProblemCodeUNSUPPORTEDMEDIATYPE,
			"Unsupported media type", "Content-Type must be application/json")
	}
	if duplicateAuthCookies(r) {
		return problemFor(r.Context(), http.StatusBadRequest, identityapi.ProblemCodeINVALIDREQUEST,
			"Invalid request", "Duplicate authentication cookies")
	}
	return nil
}

func duplicateAuthCookies(r *http.Request) bool {
	for _, name := range []string{accessCookieName, refreshCookieName, csrfCookieName} {
		if len(r.CookiesNamed(name)) > 1 {
			return true
		}
	}
	return false
}
