//go:build component

package component

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/platform/pkg/postgres"
	"github.com/horizoonn/relay/platform/pkg/security/accessjwt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/horizoonn/relay/identity/internal/app"
	"github.com/horizoonn/relay/identity/internal/config"
	"github.com/horizoonn/relay/identity/internal/domain"
	sessionrepo "github.com/horizoonn/relay/identity/internal/repository/postgres/session"
	userrepo "github.com/horizoonn/relay/identity/internal/repository/postgres/user"
)

func TestRuntimeAuthenticationCleanupAndShutdown(t *testing.T) {
	dsn := os.Getenv("RELAY_IDENTITY_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("RELAY_IDENTITY_TEST_DATABASE_URL must point to an isolated migrated Identity database")
	}
	db, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "signing.pem")
	if writeErr := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	oldPublic, oldPrivate, keyErr := ed25519.GenerateKey(nil)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	oldDER, keyErr := x509.MarshalPKIXPublicKey(oldPublic)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	oldFile := filepath.Join(t.TempDir(), "previous.pem")
	if writeErr := os.WriteFile(oldFile, pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: oldDER,
	}), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	redisOptions, err := redis.ParseURL(os.Getenv("RELAY_IDENTITY_TEST_REDIS_URL"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		Mail: config.MailConfig{
			Address:       os.Getenv("RELAY_IDENTITY_TEST_SMTP_ADDR"),
			From:          "no-reply@relay.local",
			Timeout:       time.Second,
			AllowInsecure: true,
			EncryptionKey: "test-mail-encryption-key-at-least-32-bytes",
		},
		Redis: config.RedisConfig{
			Address:        redisOptions.Addr,
			Timeout:        200 * time.Millisecond,
			MaxConnections: 4,
		},
		RateLimit: config.RateLimitConfig{
			EmailIP:      "1000/1s/1000",
			EmailAccount: "1000/1s/1000",
			ActionIP:     "1000/1s/1000",
			Key:          uuid.NewV7().String(),
			LoginIP:      "1000/1s/1000",
			LoginAccount: "1000/1s/1000",
			RegisterIP:   "1000/1s/1000",
			RefreshIP:    "1000/1s/1000",
			ReadUser:     "1000/1s/1000",
			LogoutIP:     "1000/1s/1000",
			RevokeUser:   "1000/1s/1000",
		},
		App: config.AppConfig{
			ShutdownTimeout:      2 * time.Second,
			MaxParallelPasswords: 2,
			EmailWorkers:         2,
		},
		HTTP: config.HTTPConfig{
			Address:          "127.0.0.1:0",
			AllowedOrigin:    "https://localhost",
			CursorSigningKey: "local-test-cursor-key-32-bytes-long",
		},
		Signing: config.SigningConfig{
			KeyID:          "runtime",
			KeyFile:        keyFile,
			PublicKeyFiles: map[string]string{"previous": oldFile},
		},
		Postgres: config.PostgresConfig{
			Host:           db.Host,
			Port:           db.Port,
			Database:       db.Database,
			User:           db.User,
			Password:       db.Password,
			SSLMode:        "disable",
			MaxConns:       4,
			MinConns:       0,
			ConnectTimeout: time.Second,
		},
	}
	cleanupPool, expiredSessionID := seedExpiredRuntimeSession(t, dsn)
	application, err := app.New(t.Context(), cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	finished := make(chan error, 1)
	go func() { finished <- application.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case runErr := <-finished:
			if runErr != nil {
				t.Error(runErr)
			}
		case <-time.After(3 * time.Second):
			t.Error("runtime did not stop")
		}
	})
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for application.HTTPAddress() == "" {
		select {
		case <-deadline.C:
			t.Fatal("runtime did not bind")
		case <-time.After(time.Millisecond):
		}
	}
	baseURL := "http://" + application.HTTPAddress()
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	request := func(method, path string, body []byte, accessToken string) (int, []*http.Cookie) {
		t.Helper()
		r, requestErr := http.NewRequestWithContext(t.Context(), method, baseURL+path, bytes.NewReader(body))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		r.Header.Set("Origin", cfg.HTTP.AllowedOrigin)
		r.Header.Set("Content-Type", "application/json")
		if accessToken != "" {
			r.AddCookie(&http.Cookie{
				Name:  "__Host-relay_access",
				Value: accessToken,
			})
		}
		response, requestErr := client.Do(r)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		defer func() { _ = response.Body.Close() }()
		if _, readErr := io.Copy(io.Discard, response.Body); readErr != nil {
			t.Fatal(readErr)
		}
		return response.StatusCode, response.Cookies()
	}
	for _, path := range []string{"/healthz", "/readyz"} {
		if status, _ := request(http.MethodGet, path, nil, ""); status != http.StatusOK {
			t.Fatalf("%s status=%d", path, status)
		}
	}

	cleanupCtx, stopCleanup := context.WithTimeout(t.Context(), 3*time.Second)
	defer stopCleanup()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var remaining bool
		if queryErr := cleanupPool.QueryRow(cleanupCtx,
			`SELECT EXISTS (SELECT 1 FROM identity.sessions WHERE id=$1)`, expiredSessionID).Scan(&remaining); queryErr != nil {
			t.Fatal(queryErr)
		}
		if !remaining {
			break
		}
		select {
		case <-cleanupCtx.Done():
			t.Fatal("startup cleanup did not delete the expired session")
		case <-ticker.C:
		}
	}
	email := uuid.NewV7().String() + "@example.com"
	t.Cleanup(func() {
		cleanupCtx, stopCleanup := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
		defer stopCleanup()
		connection, connectErr := pgx.Connect(cleanupCtx, dsn)
		if connectErr != nil {
			t.Error(connectErr)
			return
		}
		defer func() { _ = connection.Close(cleanupCtx) }()
		if _, deleteErr := connection.Exec(
			cleanupCtx,
			`DELETE FROM identity.users WHERE email = $1`,
			email,
		); deleteErr != nil {
			t.Error(deleteErr)
		}
	})
	body, err := json.Marshal(map[string]string{"email": email, "password": "runtime long password"})
	if err != nil {
		t.Fatal(err)
	}
	if status, cookies := request(http.MethodPost, "/api/v1/auth/register", body, ""); status != http.StatusCreated ||
		len(cookies) != 0 {
		t.Fatalf("register status=%d cookies=%d", status, len(cookies))
	}
	token := waitMailpitToken(t, client, email, "Confirm your Relay email")
	verifyBody, marshalErr := json.Marshal(map[string]string{"token": token})
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if status, _ := request(http.MethodPost, "/api/v1/auth/email/verification", verifyBody, ""); status != 204 {
		t.Fatalf("verify=%d", status)
	}
	status, cookies := request(http.MethodPost, "/api/v1/auth/login", body, "")
	if status != http.StatusOK || len(cookies) != 3 {
		t.Fatalf("login status=%d cookies=%d", status, len(cookies))
	}
	verifier, err := accessjwt.NewVerifier(map[string]ed25519.PublicKey{"runtime": public})
	if err != nil {
		t.Fatal(err)
	}
	verified := false
	for _, cookie := range cookies {
		if cookie.Name == "__Host-relay_access" {
			access, verifyErr := verifier.Verify(cookie.Value)
			if verifyErr != nil {
				t.Fatal(verifyErr)
			}
			oldIssuer, issueErr := accessjwt.NewIssuer("previous", oldPrivate)
			if issueErr != nil {
				t.Fatal(issueErr)
			}
			oldToken, issueErr := oldIssuer.Issue(access.UserID, access.SessionID, access.CSRFHash, time.Now().Add(time.Hour))
			if issueErr != nil {
				t.Fatal(issueErr)
			}
			for _, raw := range []string{cookie.Value, oldToken.Raw} {
				if getStatus, getCookies := request(http.MethodGet, "/api/v1/auth/session", nil, raw); getStatus != 200 ||
					len(getCookies) != 0 {
					t.Fatal("current or previous key token rejected by runtime")
				}
			}
			verified = true
		}
	}
	if !verified {
		t.Fatal("runtime did not issue access signed by its configured key")
	}
}

func seedExpiredRuntimeSession(t *testing.T, dsn string) (*pgxpool.Pool, uuid.UUID) {
	t.Helper()
	pool, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	tx := postgres.NewTxManager(pool)
	users := userrepo.NewRepository(tx.Executor, time.Second)
	sessions := sessionrepo.NewRepository(tx.Executor, time.Second)
	created := time.Now().UTC().Add(-4 * time.Hour)
	user, err := domain.NewUser(uuid.NewV7().String()+"@example.com", created)
	if err != nil {
		t.Fatal(err)
	}
	if err = users.Create(t.Context(), user, "unused-by-cleanup"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, deleteErr := pool.Exec(ctx, `DELETE FROM identity.users WHERE id=$1`, user.ID); deleteErr != nil {
			t.Error(deleteErr)
		}
	})
	session, err := domain.NewSession(user.ID, [32]byte{1}, created, created.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := sessions.Create(t.Context(), session, sha256.Sum256([]byte(session.ID.String()))); err != nil {
		t.Fatal(err)
	}
	return pool, session.ID
}
