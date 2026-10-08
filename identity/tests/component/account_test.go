//go:build component

package component

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/identity/internal/secret"
	"github.com/horizoonn/relay/identity/internal/usecase/email"
)

type captureMail struct {
	mu       sync.Mutex
	messages []email.Mail
	failure  error
}

func (m *captureMail) Send(_ context.Context, mail email.Mail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failure != nil {
		return m.failure
	}
	m.messages = append(m.messages, mail)
	return nil
}

func mailToken(t *testing.T, body string) string {
	t.Helper()
	_, value, found := strings.Cut(body, "#token=")
	if !found {
		t.Fatal("email does not contain an action link")
	}
	value, _, _ = strings.Cut(value, "\r\n")
	if len(value) != 43 {
		t.Fatal("invalid email token length")
	}
	return value
}

func (f *fixture) deliverToken(t *testing.T, email string) string {
	t.Helper()
	for range 100 {
		worked, err := f.delivery.DeliverOne(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		f.mail.mu.Lock()
		for _, mail := range f.mail.messages {
			if mail.To == strings.Replace(email, "EXAMPLE.COM", "example.com", 1) {
				body := mail.Body
				f.mail.mu.Unlock()
				return mailToken(t, body)
			}
		}
		f.mail.mu.Unlock()
		if !worked {
			t.Fatal("no pending email for account")
		}
	}
	t.Fatal("email delivery did not reach account")
	return ""
}

func (f *fixture) accountPost(
	t *testing.T,
	path string,
	value map[string]string,
) (int, http.Header, []byte) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return rateRequest(t, f, http.MethodPost, path, body, nil)
}

func (f *fixture) verifyRegistered(t *testing.T, email string) {
	t.Helper()
	token := f.deliverToken(t, email)
	if status, _, _ := f.accountPost(
		t,
		"/api/v1/auth/email/verification",
		map[string]string{"token": token},
	); status != 204 {
		t.Fatalf("verify status=%d", status)
	}
}

func TestEmailVerificationAndPasswordRecovery(t *testing.T) {
	f := newFixture(t, false)
	email := uuid.NewV7().String() + "@example.com"
	const oldPassword = "original sufficiently long password"
	const newPassword = "replacement sufficiently long password"
	response, data := f.post(t, "/api/v1/auth/register", email, oldPassword)
	if response.status != 201 {
		t.Fatalf("register=%d", response.status)
	}
	var registered struct {
		ID string `json:"user_id"`
	}
	if err := json.Unmarshal(data, &registered); err != nil {
		t.Fatal(err)
	}
	id, err := uuid.Parse(registered.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, deleteErr := f.pool.Exec(context.WithoutCancel(t.Context()), `DELETE FROM identity.users WHERE id=$1`, id)
		if deleteErr != nil {
			t.Error(deleteErr)
		}
	})
	for _, tc := range []struct {
		name     string
		password string
		status   int
	}{
		{
			name:     "unverified correct password",
			password: oldPassword,
			status:   403,
		}, {
			name:     "unverified wrong password",
			password: "incorrect",
			status:   401,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := f.post(t, "/api/v1/auth/login", email, tc.password)
			if got.status != tc.status {
				t.Fatalf("status=%d", got.status)
			}
		})
	}
	verify := f.deliverToken(t, email)
	for _, tc := range []struct {
		name   string
		path   string
		token  string
		status int
	}{
		{
			name:   "wrong purpose",
			path:   "/api/v1/auth/password/reset",
			token:  verify,
			status: 400,
		},
		{
			name:   "malformed token",
			path:   "/api/v1/auth/email/verification",
			token:  "invalid",
			status: 400,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := map[string]string{"token": tc.token}
			if tc.path == "/api/v1/auth/password/reset" {
				body["password"] = newPassword
			}
			status, _, _ := f.accountPost(t, tc.path, body)
			if status != tc.status {
				t.Fatalf("status=%d", status)
			}
		})
	}
	if status, _, _ := f.accountPost(
		t,
		"/api/v1/auth/email/verification",
		map[string]string{"token": verify},
	); status != 204 {
		t.Fatalf("confirm=%d", status)
	}
	if status, _, _ := f.accountPost(
		t,
		"/api/v1/auth/email/verification",
		map[string]string{"token": verify},
	); status != 400 {
		t.Fatalf("used verify=%d", status)
	}

	login, _ := f.post(t, "/api/v1/auth/login", email, oldPassword)
	if login.status != 200 {
		t.Fatalf("login=%d", login.status)
	}

	login, _ = f.post(t, "/api/v1/auth/login", email, oldPassword)
	if login.status != 200 {
		t.Fatalf("second login=%d", login.status)
	}
	f.mail.mu.Lock()
	f.mail.messages = nil
	f.mail.mu.Unlock()
	for _, tc := range []struct {
		name  string
		email string
	}{{
		name:  "existing account",
		email: email,
	}, {
		name:  "unknown account",
		email: uuid.NewV7().String() + "@example.com",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			status, headers, body := f.accountPost(
				t,
				"/api/v1/auth/password/reset-requests",
				map[string]string{"email": tc.email},
			)
			if status != 202 || len(headers.Values("Set-Cookie")) != 0 || len(body) != 0 {
				t.Fatalf("status=%d body length=%d", status, len(body))
			}
		})
	}
	reset := f.deliverToken(t, email)

	status, _, _ := f.accountPost(t, "/api/v1/auth/password/reset-requests", map[string]string{"email": email})
	if status != 202 {
		t.Fatal(status)
	}
	if status, _, _ := f.accountPost(
		t,
		"/api/v1/auth/password/reset",
		map[string]string{
			"token":    reset,
			"password": "short",
		},
	); status != 400 {
		t.Fatalf("weak reset=%d", status)
	}
	if status, headers, _ := f.accountPost(
		t,
		"/api/v1/auth/password/reset",
		map[string]string{
			"token":    reset,
			"password": newPassword,
		},
	); status != 204 ||
		len(headers.Values("Set-Cookie")) != 3 {
		t.Fatalf("reset=%d", status)
	}
	if status, _, _ := f.accountPost(
		t,
		"/api/v1/auth/password/reset",
		map[string]string{
			"token":    reset,
			"password": newPassword,
		},
	); status != 400 {
		t.Fatalf("used reset=%d", status)
	}

	var active int
	if err := f.pool.QueryRow(
		t.Context(),
		`SELECT count(*) FROM identity.sessions WHERE user_id=$1 AND revoked_at IS NULL`,
		id,
	).Scan(&active); err != nil ||
		active != 0 {
		t.Fatalf("active=%d err=%v", active, err)
	}
	before := len(f.mail.messages)
	for range 10 {
		worked, err := f.delivery.DeliverOne(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if !worked {
			break
		}
	}
	if len(f.mail.messages) != before+1 || f.mail.messages[before].Subject != "Your Relay password was changed" {
		t.Fatal("a queued request from before password change minted a fresh token")
	}
	for _, tc := range []struct {
		name     string
		password string
		status   int
	}{{
		name:     "old password rejected",
		password: oldPassword,
		status:   401,
	}, {
		name:     "new password accepted",
		password: newPassword,
		status:   200,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			response, _ := f.post(t, "/api/v1/auth/login", email, tc.password)
			if response.status != tc.status {
				t.Fatalf("status=%d", response.status)
			}
		})
	}
}

func TestEmailRetryAfterTokenUse(t *testing.T) {
	f := newFixture(t, false)
	email := uuid.NewV7().String() + "@example.com"
	response, data := f.post(t, "/api/v1/auth/register", email, "sufficiently long password")
	if response.status != 201 {
		t.Fatal(response.status)
	}
	var registered struct {
		ID string `json:"user_id"`
	}
	if err := json.Unmarshal(data, &registered); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, err := f.pool.Exec(context.WithoutCancel(t.Context()), `DELETE FROM identity.users WHERE id=$1`, registered.ID)
		if err != nil {
			t.Error(err)
		}
	})
	f.mail.failure = errors.New("SMTP temporarily unavailable")
	worked, err := f.delivery.DeliverOne(t.Context())
	if !worked || err == nil {
		t.Fatal("SMTP failure did not retain the job")
	}
	var payload []byte
	var prepared string
	var created, expires time.Time
	if err := f.pool.QueryRow(
		t.Context(),
		`SELECT encrypted_payload, prepared_user_id::text, created_at, expires_at
		 FROM identity.email_jobs
		 WHERE prepared_user_id = $1`,
		registered.ID,
	).Scan(
		&payload,
		&prepared,
		&created,
		&expires,
	); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), email) {
		t.Fatal("email payload was persisted as plaintext")
	}
	f.mail.failure = nil
	if _, err := f.pool.Exec(
		t.Context(),
		`UPDATE identity.email_jobs SET available_at=$2 WHERE prepared_user_id=$1`,
		registered.ID,
		time.Now().UTC(),
	); err != nil {
		t.Fatal(err)
	}
	token := f.deliverToken(t, email)
	if err := f.accounts.VerifyEmail(t.Context(), token); err != nil {
		t.Fatal(err)
	}

	if _, err := f.pool.Exec(
		t.Context(),
		`INSERT INTO identity.email_jobs (
		    id, encrypted_payload, prepared_user_id, created_at, expires_at, available_at
		 ) VALUES ($1, $2, $3, $4, $5, $4)`,
		uuid.NewV7(),
		payload,
		prepared,
		created,
		expires,
	); err != nil {
		t.Fatal(err)
	}
	before := len(f.mail.messages)
	if _, err := f.delivery.DeliverOne(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(f.mail.messages) != before {
		t.Fatal("consumed verification was emailed again")
	}

	var count int
	if err := f.pool.QueryRow(
		t.Context(),
		`SELECT count(*) FROM identity.account_tokens WHERE user_id=$1 AND used_at IS NULL`,
		registered.ID,
	).Scan(&count); err != nil ||
		count != 0 {
		t.Fatalf("active tokens=%d err=%v", count, err)
	}
}

func TestAccountTokenErrors(t *testing.T) {
	for _, tc := range []struct {
		name     string
		reset    bool
		expired  bool
		disabled bool
	}{
		{
			name:     "expired verification",
			reset:    false,
			expired:  true,
			disabled: false,
		}, {
			name:     "disabled verification",
			reset:    false,
			expired:  false,
			disabled: true,
		}, {
			name:     "expired recovery",
			reset:    true,
			expired:  true,
			disabled: false,
		}, {
			name:     "disabled recovery",
			reset:    true,
			expired:  false,
			disabled: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, false)
			email := uuid.NewV7().String() + "@example.com"
			id := f.registerUnverified(t, email, "sufficiently long password")
			token := f.deliverToken(t, email)
			path := "/api/v1/auth/email/verification"
			body := map[string]string{"token": token}
			if tc.reset {
				f.mail.messages = nil
				if status, _, _ := f.accountPost(
					t,
					"/api/v1/auth/password/reset-requests",
					map[string]string{"email": email},
				); status != 202 {
					t.Fatal(status)
				}
				token = f.deliverToken(t, email)
				path = "/api/v1/auth/password/reset"
				body = map[string]string{"token": token, "password": "replacement sufficiently long password"}
			}
			if tc.expired {
				hash, err := secret.Digest(token)
				if err != nil {
					t.Fatal(err)
				}
				expires := time.Now().UTC().Add(-time.Second)
				ttl := time.Hour
				if tc.reset {
					ttl = 15 * time.Minute
				}
				if _, err := f.pool.Exec(
					t.Context(),
					`UPDATE identity.account_tokens SET created_at=$2,expires_at=$3 WHERE token_hash=$1`,
					hash[:],
					expires.Add(-ttl),
					expires,
				); err != nil {
					t.Fatal(err)
				}
			}
			if tc.disabled {
				if _, err := f.pool.Exec(t.Context(), `UPDATE identity.users SET state='disabled' WHERE id=$1`, id); err != nil {
					t.Fatal(err)
				}
			}
			if status, headers, _ := f.accountPost(t, path, body); status != 400 || len(headers.Values("Set-Cookie")) != 0 {
				t.Fatalf("status=%d", status)
			}
		})
	}
}

func TestAccountClockRollback(t *testing.T) {
	for _, action := range []string{"verification", "password reset"} {
		t.Run(action, func(t *testing.T) {
			f := newFixture(t, false)
			address := uuid.NewV7().String() + "@example.com"
			id := f.registerUnverified(t, address, "original password with sufficient length")
			if action == "password reset" {
				f.deliverToken(t, address)
				f.mail.mu.Lock()
				f.mail.messages = nil
				f.mail.mu.Unlock()
				status, _, _ := f.accountPost(t, "/api/v1/auth/password/reset-requests", map[string]string{"email": address})
				if status != http.StatusAccepted {
					t.Fatalf("reset request status=%d", status)
				}
			}
			raw := f.deliverToken(t, address)
			// Existing timestamps are ahead of the current clock, as after a clock rollback.
			createdAt := time.Now().UTC().Truncate(time.Microsecond).Add(time.Minute)
			updatedAt := createdAt.Add(time.Minute)
			if _, err := f.pool.Exec(t.Context(), `UPDATE identity.users SET created_at=$2, updated_at=$3 WHERE id=$1`, id, createdAt, updatedAt); err != nil {
				t.Fatal(err)
			}
			path := "/api/v1/auth/email/verification"
			payload := map[string]string{"token": raw}
			if action == "password reset" {
				path = "/api/v1/auth/password/reset"
				payload["password"] = "replacement password with sufficient length"
			}
			status, _, _ := f.accountPost(t, path, payload)
			if status != http.StatusNoContent {
				t.Fatalf("account action status=%d", status)
			}
			var storedCreated, storedUpdated, verifiedAt time.Time
			if err := f.pool.QueryRow(t.Context(), `SELECT created_at, updated_at, email_verified_at FROM identity.users WHERE id=$1`, id).Scan(&storedCreated, &storedUpdated, &verifiedAt); err != nil {
				t.Fatal(err)
			}
			if !storedCreated.Equal(createdAt) || !storedUpdated.Equal(updatedAt) || !verifiedAt.Equal(updatedAt) {
				t.Fatalf("timestamps moved backwards: created=%s updated=%s verified=%s", storedCreated, storedUpdated, verifiedAt)
			}
			status, _, _ = f.accountPost(t, path, payload)
			if status != http.StatusBadRequest {
				t.Fatalf("consumed token status=%d; want 400", status)
			}
		})
	}
}
