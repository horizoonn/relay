package identityv1

import (
	"net/http"
	"time"
)

const (
	accessCookieName  = "__Host-relay_access"
	refreshCookieName = "__Secure-relay_refresh"
	csrfCookieName    = "__Host-relay_csrf"
)

func sessionCookies(
	access string,
	refresh string,
	csrf string,
	accessExpiry time.Time,
	sessionExpiry time.Time,
) []string {
	return []string{
		(&http.Cookie{
			Name:     accessCookieName,
			Value:    access,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Expires:  accessExpiry,
		}).String(),
		(&http.Cookie{
			Name:     refreshCookieName,
			Value:    refresh,
			Path:     "/api/v1/auth",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Expires:  sessionExpiry,
		}).String(),
		(&http.Cookie{ //nolint:gosec // JavaScript reads this non-auth cookie to set X-CSRF-Token.
			Name:     csrfCookieName,
			Value:    csrf,
			Path:     "/",
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			Expires:  sessionExpiry,
		}).String(),
	}
}

func clearSessionCookies() []string {
	return []string{
		(&http.Cookie{
			Name:     accessCookieName,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
			Expires:  time.Unix(1, 0),
		}).String(),
		(&http.Cookie{
			Name:     refreshCookieName,
			Path:     "/api/v1/auth",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
			Expires:  time.Unix(1, 0),
		}).String(),
		(&http.Cookie{ //nolint:gosec // Same JavaScript-readable CSRF cookie as login.
			Name:     csrfCookieName,
			Path:     "/",
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
			Expires:  time.Unix(1, 0),
		}).String(),
	}
}
