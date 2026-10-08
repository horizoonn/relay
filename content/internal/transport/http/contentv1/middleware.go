package contentv1

import (
	"net/http"

	"github.com/horizoonn/relay/platform/pkg/httpmiddleware"
	contentapi "github.com/horizoonn/relay/shared/pkg/openapi/content/v1"
)

const maxJSONBodyBytes = 512 << 10

func requestIDMiddleware(next http.Handler) http.Handler {
	return httpmiddleware.RequestIDs(httpmiddleware.PrivateResponses(next))
}

func (h *Handler) browserSecurity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, name := range []string{"__Host-relay_access", "__Host-relay_csrf"} {
			if len(r.CookiesNamed(name)) > 1 {
				h.writeProblem(w, problemFor(r.Context(), http.StatusBadRequest, contentapi.ProblemCodeINVALIDREQUEST,
					"Invalid request", "Duplicate authentication cookies"))
				return
			}
		}
		request := browserRequest{
			origin:          r.Header.Get("Origin"),
			originCount:     len(r.Header.Values("Origin")),
			csrfHeaderCount: len(r.Header.Values("X-CSRF-Token")),
		}
		if cookie, err := r.Cookie("__Host-relay_csrf"); err == nil {
			request.csrfCookie = cookie.Value
		}
		next.ServeHTTP(w, r.WithContext(withBrowserRequest(r.Context(), request)))
	})
}

func bodyLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}
