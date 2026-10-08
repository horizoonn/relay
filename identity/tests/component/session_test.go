//go:build component

package component

import (
	"encoding/base64"
	"encoding/json/v2"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/golang-jwt/jwt/v5"
)

func (f *fixture) currentSession(t *testing.T, cookie string) (int, []byte) {
	t.Helper()
	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.server.URL+"/api/v1/auth/session", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cookie != "" {
		r.Header.Set("Cookie", cookie)
	}
	client := *f.server.Client()
	client.Jar = nil
	client.Timeout = 5 * time.Second
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Header.Values("Set-Cookie")) != 0 || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("GET changed cookies or can be cached")
	}
	return response.StatusCode, data
}

func TestCurrentSessionThroughHTTPS(t *testing.T) {
	f := newFixture(t, false)
	email := uuid.NewV7().String() + "@example.com"
	id := f.registerVerified(t, email, "long password for session")
	login, _ := f.post(t, "/api/v1/auth/login", email, "long password for session")
	if login.status != 200 {
		t.Fatal("login failed")
	}
	var raw string
	for _, cookie := range login.cookies {
		if cookie.Name == "__Host-relay_access" {
			raw = cookie.Value
		}
	}
	access, err := f.verifier.Verify(raw)
	if err != nil {
		t.Fatal(err)
	}
	cookie := "__Host-relay_access=" + raw
	var beforeSeen, beforeExpiry time.Time
	var beforeGeneration int64
	const activeCredentialQuery = `
		SELECT s.last_seen_at, s.expires_at, r.generation
		FROM identity.sessions s
		JOIN identity.refresh_credentials r ON r.session_id = s.id
		WHERE s.id = $1 AND r.used_at IS NULL
	`
	if err := f.pool.QueryRow(t.Context(), activeCredentialQuery, access.SessionID).Scan(
		&beforeSeen,
		&beforeExpiry,
		&beforeGeneration,
	); err != nil {
		t.Fatal(err)
	}
	status, data := f.currentSession(t, cookie)
	if status != 200 {
		t.Fatalf("current session status=%d", status)
	}
	var profile struct {
		UserID          string    `json:"user_id"`
		Email           string    `json:"email"`
		Verified        bool      `json:"email_verified"`
		SessionID       string    `json:"session_id"`
		AccessExpiresAt time.Time `json:"access_expires_at"`
	}
	if err := json.Unmarshal(data, &profile); err != nil {
		t.Fatal(err)
	}
	if profile.UserID != id.String() ||
		profile.Email != email ||
		!profile.Verified ||
		profile.SessionID != access.SessionID.String() ||
		!profile.AccessExpiresAt.Equal(access.ExpiresAt) ||
		strings.Contains(string(data), raw) ||
		strings.Contains(string(data), "csrf_hash") {
		t.Fatal("incorrect current account/session response")
	}
	var afterSeen, afterExpiry time.Time
	var afterGeneration int64
	if err := f.pool.QueryRow(t.Context(), activeCredentialQuery, access.SessionID).Scan(
		&afterSeen,
		&afterExpiry,
		&afterGeneration,
	); err != nil {
		t.Fatal(err)
	}
	if !beforeSeen.Equal(afterSeen) || !beforeExpiry.Equal(afterExpiry) || beforeGeneration != afterGeneration {
		t.Fatal("GET changed activity, expiry or refresh generation")
	}

	if _, err := f.pool.Exec(t.Context(), `DELETE FROM identity.password_credentials WHERE user_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if passwordlessStatus, _ := f.currentSession(t, cookie); passwordlessStatus != 200 {
		t.Fatal("session lookup requires a password credential")
	}
	if _, err := f.pool.Exec(
		t.Context(),
		`UPDATE identity.users SET email_verified_at=now() WHERE id=$1`,
		id,
	); err != nil {
		t.Fatal(err)
	}
	status, data = f.currentSession(t, cookie)
	if status != 200 {
		t.Fatal("verified account rejected")
	}
	if err := json.Unmarshal(data, &profile); err != nil || !profile.Verified {
		t.Fatal("current email verification was not loaded")
	}

	for _, tc := range []struct {
		name   string
		cookie string
		status int
		code   string
	}{
		{
			name:   "missing",
			cookie: "",
			status: 401,
			code:   "UNAUTHENTICATED",
		},
		{
			name:   "invalid",
			cookie: "__Host-relay_access=invalid",
			status: 401,
			code:   "UNAUTHENTICATED",
		},
		{
			name:   "duplicate",
			cookie: cookie + "; " + cookie,
			status: 400,
			code:   "INVALID_REQUEST",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, data := f.currentSession(t, tc.cookie)
			if status != tc.status {
				t.Fatalf("status=%d", status)
			}
			var problem struct {
				Code   string `json:"code"`
				Status int    `json:"status"`
			}
			if err := json.Unmarshal(data, &problem); err != nil || problem.Code != tc.code || problem.Status != status {
				t.Fatal("inconsistent authentication problem")
			}
		})
	}
	for _, tc := range []struct {
		name  string
		query string
	}{
		{
			name:  "disabled",
			query: `UPDATE identity.users SET state='disabled' WHERE id=$1`,
		},
		{
			name:  "revoked",
			query: `UPDATE identity.sessions SET revoked_at=now() WHERE user_id=$1`,
		},
		{
			name: "expired",
			query: `
				UPDATE identity.sessions
				SET created_at = now() - interval '2 hours',
				    authenticated_at = now() - interval '2 hours',
				    last_seen_at = now() - interval '2 hours',
				    expires_at = now() - interval '1 hour'
				WHERE user_id = $1
			`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := f.pool.Exec(t.Context(), tc.query, id); err != nil {
				t.Fatal(err)
			}
			status, data := f.currentSession(t, cookie)
			if status != 401 || !strings.Contains(string(data), `"code":"UNAUTHENTICATED"`) {
				t.Fatalf("inactive session status=%d", status)
			}
			if _, err := f.verifier.Verify(raw); err != nil {
				t.Fatal("test access is no longer cryptographically valid")
			}
			if _, err := f.pool.Exec(t.Context(), `UPDATE identity.users SET state='active' WHERE id=$1`, id); err != nil {
				t.Fatal(err)
			}
			if _, err := f.pool.Exec(
				t.Context(),
				`UPDATE identity.sessions SET revoked_at=NULL WHERE user_id=$1`,
				id,
			); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSessionOwnerAndAccessExpiry(t *testing.T) {
	f := newFixture(t, false)
	id := f.registerVerified(t, uuid.NewV7().String()+"@example.com", "another session password")
	token, err := f.issuer.Issue(id, uuid.NewV7(), [32]byte{1}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := f.currentSession(t, "__Host-relay_access="+token.Raw); status != 401 {
		t.Fatal("missing session accepted")
	}
	otherEmail := uuid.NewV7().String() + "@example.com"
	f.registerVerified(t, otherEmail, "other user session password")
	login, _ := f.post(t, "/api/v1/auth/login", otherEmail, "other user session password")
	var otherSID uuid.UUID
	for _, cookie := range login.cookies {
		if cookie.Name == "__Host-relay_access" {
			access, verifyErr := f.verifier.Verify(cookie.Value)
			if verifyErr != nil {
				t.Fatal(verifyErr)
			}
			otherSID = access.SessionID
		}
	}
	token, err = f.issuer.Issue(id, otherSID, [32]byte{1}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := f.currentSession(t, "__Host-relay_access="+token.Raw); status != 401 {
		t.Fatalf("foreign session status=%d, want 401", status)
	}

	issuedAt := time.Now().Unix() - 301
	csrfHash := [32]byte{1}
	expired := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": "relay-identity", "aud": "relay-api", "sub": id.String(), "sid": otherSID.String(),
		"iat": issuedAt, "exp": issuedAt + 300, "csrf_hash": base64.RawURLEncoding.EncodeToString(csrfHash[:]),
	})
	expired.Header["kid"] = "component"
	expired.Header["typ"] = "relay-at+jwt"
	raw, err := expired.SignedString(f.private)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := f.currentSession(t, "__Host-relay_access="+raw); status != 401 {
		t.Fatal("expired access accepted")
	}
}
