//go:build component

package component

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"testing"
	"uuid"

	"golang.org/x/crypto/argon2"

	"github.com/horizoonn/relay/identity/internal/password"
)

func TestPasswordRecoverySurvivesLoginRehash(t *testing.T) {
	const value = "original sufficiently long password"
	salt := []byte("a test salt only!")
	key := argon2.IDKey([]byte(value), salt, 2, 19*1024, 1, 32)
	oldHash := fmt.Sprintf("$argon2id$v=19$m=19456,t=2,p=1$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))

	for _, tc := range []struct {
		name     string
		prepared bool
	}{
		{
			name: "email queued before rehash",
		},
		{
			name:     "email prepared before rehash",
			prepared: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, false)
			email := uuid.NewV7().String() + "@example.com"
			id := f.registerVerified(t, email, value)
			f.mail.mu.Lock()
			f.mail.messages = nil
			f.mail.mu.Unlock()
			if _, err := f.pool.Exec(
				t.Context(),
				`UPDATE identity.password_credentials SET password_hash = $2 WHERE user_id = $1`,
				id,
				oldHash,
			); err != nil {
				t.Fatal(err)
			}
			status, _, _ := f.accountPost(
				t,
				"/api/v1/auth/password/reset-requests",
				map[string]string{"email": email},
			)
			if status != http.StatusAccepted {
				t.Fatalf("request password recovery status=%d", status)
			}
			var token string
			if tc.prepared {
				token = f.deliverToken(t, email)
			}
			login, _ := f.post(t, "/api/v1/auth/login", email, value)
			if login.status != http.StatusOK {
				t.Fatalf("login status=%d", login.status)
			}
			var storedHash string
			if err := f.pool.QueryRow(
				t.Context(),
				`SELECT password_hash FROM identity.password_credentials WHERE user_id = $1`,
				id,
			).Scan(&storedHash); err != nil {
				t.Fatal(err)
			}
			needed, err := password.NeedsRehash(storedHash)
			if err != nil || needed {
				t.Fatalf("login did not upgrade the password hash: %v", err)
			}
			if !tc.prepared {
				token = f.deliverToken(t, email)
			}
			status, _, _ = f.accountPost(
				t,
				"/api/v1/auth/password/reset",
				map[string]string{
					"token":    token,
					"password": "replacement sufficiently long password",
				},
			)
			if status != http.StatusNoContent {
				t.Fatalf("password recovery after rehash status=%d", status)
			}
		})
	}
}
