package accessjwt

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/golang-jwt/jwt/v5"
)

func TestIssueAndVerify(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.September, 29, 12, 0, 0, 0, time.UTC)
	issuer, err := NewIssuer("key-1", private)
	if err != nil {
		t.Fatal(err)
	}
	issuer.now = func() time.Time { return now }
	verifier, err := NewVerifier(map[string]ed25519.PublicKey{"key-1": public})
	if err != nil {
		t.Fatal(err)
	}
	verifier.now = func() time.Time { return now }

	userID, sessionID := uuid.NewV7(), uuid.NewV7()
	csrfHash := [32]byte{1, 2, 3}
	raw, err := issuer.Issue(userID, sessionID, csrfHash, now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	access, err := verifier.Verify(raw.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if access.UserID != userID || access.SessionID != sessionID || access.CSRFHash != csrfHash {
		t.Fatalf("unexpected access principal: %+v", access)
	}
	if !access.ExpiresAt.Equal(raw.ExpiresAt) || !access.ExpiresAt.Equal(now.Add(30*time.Second)) {
		t.Fatalf("access expiry = %s", access.ExpiresAt)
	}

	verifier.now = func() time.Time { return now.Add(30 * time.Second) }
	if _, err := verifier.Verify(raw.Raw); err == nil {
		t.Fatal("expired token accepted")
	}
}

func TestVerifierRejectsWrongTokenOrClaims(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.September, 29, 12, 0, 0, 0, time.UTC)
	verifier, err := NewVerifier(map[string]ed25519.PublicKey{"key-1": public})
	if err != nil {
		t.Fatal(err)
	}
	verifier.now = func() time.Time { return now }
	base := claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "relay-identity",
			Subject:   uuid.NewV7().String(),
			Audience:  jwt.ClaimStrings{"relay-api"},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
		},
		SessionID: uuid.NewV7().String(),
		CSRFHash:  base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}
	tests := []struct {
		name string
		edit func(*claims, *jwt.Token)
	}{
		{
			name: "wrong type",
			edit: func(_ *claims, token *jwt.Token) {
				token.Header["typ"] = "JWT"
			},
		},
		{
			name: "unknown key",
			edit: func(_ *claims, token *jwt.Token) {
				token.Header["kid"] = "unknown"
			},
		},
		{
			name: "numeric key id",
			edit: func(_ *claims, token *jwt.Token) {
				token.Header["kid"] = 1
			},
		},
		{
			name: "wrong issuer",
			edit: func(c *claims, _ *jwt.Token) {
				c.Issuer = "other"
			},
		},
		{
			name: "wrong audience",
			edit: func(c *claims, _ *jwt.Token) {
				c.Audience = jwt.ClaimStrings{"other"}
			},
		},
		{
			name: "missing audience",
			edit: func(c *claims, _ *jwt.Token) {
				c.Audience = nil
			},
		},
		{
			name: "extra audience",
			edit: func(c *claims, _ *jwt.Token) {
				c.Audience = jwt.ClaimStrings{"relay-api", "other"}
			},
		},
		{
			name: "missing expiry",
			edit: func(c *claims, _ *jwt.Token) {
				c.ExpiresAt = nil
			},
		},
		{
			name: "missing issued at",
			edit: func(c *claims, _ *jwt.Token) {
				c.IssuedAt = nil
			},
		},
		{
			name: "future issued at",
			edit: func(c *claims, _ *jwt.Token) {
				c.IssuedAt = jwt.NewNumericDate(now.Add(31 * time.Second))
			},
		},
		{
			name: "issued after expiry",
			edit: func(c *claims, _ *jwt.Token) {
				c.IssuedAt = jwt.NewNumericDate(now.Add(10 * time.Second))
				c.ExpiresAt = jwt.NewNumericDate(now.Add(time.Second))
			},
		},
		{
			name: "excessive lifetime",
			edit: func(c *claims, _ *jwt.Token) {
				c.ExpiresAt = jwt.NewNumericDate(now.Add(6 * time.Minute))
			},
		},
		{
			name: "invalid user",
			edit: func(c *claims, _ *jwt.Token) {
				c.Subject = "not-a-uuid"
			},
		},
		{
			name: "nil user",
			edit: func(c *claims, _ *jwt.Token) {
				c.Subject = uuid.Nil().String()
			},
		},
		{
			name: "invalid session",
			edit: func(c *claims, _ *jwt.Token) {
				c.SessionID = "not-a-uuid"
			},
		},
		{
			name: "invalid csrf hash",
			edit: func(c *claims, _ *jwt.Token) {
				c.CSRFHash = "bad"
			},
		},
		{
			name: "padded csrf hash",
			edit: func(c *claims, _ *jwt.Token) {
				c.CSRFHash += "="
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := base
			token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, &data)
			token.Header["typ"] = "relay-at+jwt"
			token.Header["kid"] = "key-1"
			tc.edit(&data, token)
			raw, signErr := token.SignedString(private)
			if signErr != nil {
				t.Fatal(signErr)
			}
			if _, verifyErr := verifier.Verify(raw); verifyErr == nil {
				t.Fatal("invalid token accepted")
			}
		})
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, base)
	token.Header["typ"] = "relay-at+jwt"
	token.Header["kid"] = "key-1"
	wrongAlg, err := token.SignedString([]byte("not-the-ed25519-key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(wrongAlg); err == nil {
		t.Fatal("wrong algorithm accepted")
	}
	if _, err := verifier.Verify(strings.Repeat("x", 4097)); err == nil {
		t.Fatal("oversized token accepted")
	}
}

func TestVerifierKeyRotation(t *testing.T) {
	oldPublic, oldPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	newPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := NewIssuer("old", oldPrivate)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := issuer.Issue(uuid.NewV7(), uuid.NewV7(), [32]byte{1}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	withOld, err := NewVerifier(map[string]ed25519.PublicKey{"old": oldPublic, "new": newPublic})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = withOld.Verify(raw.Raw); err != nil {
		t.Fatal(err)
	}
	withoutOld, err := NewVerifier(map[string]ed25519.PublicKey{"new": newPublic})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := withoutOld.Verify(raw.Raw); err == nil {
		t.Fatal("token from removed key accepted")
	}
}

func TestIssuerRejectsInvalidInput(t *testing.T) {
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := NewIssuer("current", private)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		issuer    *Issuer
		userID    uuid.UUID
		sessionID uuid.UUID
		csrfHash  [32]byte
		expiresAt time.Time
	}{
		{
			name:      "missing user",
			issuer:    issuer,
			userID:    uuid.Nil(),
			sessionID: uuid.NewV7(),
			csrfHash:  [32]byte{1},
			expiresAt: time.Now().Add(time.Hour),
		},
		{
			name:      "missing session",
			issuer:    issuer,
			userID:    uuid.NewV7(),
			sessionID: uuid.Nil(),
			csrfHash:  [32]byte{1},
			expiresAt: time.Now().Add(time.Hour),
		},
		{
			name:      "missing CSRF hash",
			issuer:    issuer,
			userID:    uuid.NewV7(),
			sessionID: uuid.NewV7(),
			csrfHash:  [32]byte{},
			expiresAt: time.Now().Add(time.Hour),
		},
		{
			name:      "expired session",
			issuer:    issuer,
			userID:    uuid.NewV7(),
			sessionID: uuid.NewV7(),
			csrfHash:  [32]byte{1},
			expiresAt: time.Now().Add(-time.Minute),
		},
		{
			name:      "uninitialized issuer",
			issuer:    new(Issuer),
			userID:    uuid.NewV7(),
			sessionID: uuid.NewV7(),
			csrfHash:  [32]byte{1},
			expiresAt: time.Now().Add(time.Hour),
		},
		{
			name:      "nil issuer",
			issuer:    nil,
			userID:    uuid.NewV7(),
			sessionID: uuid.NewV7(),
			csrfHash:  [32]byte{1},
			expiresAt: time.Now().Add(time.Hour),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, issueErr := tt.issuer.Issue(tt.userID, tt.sessionID, tt.csrfHash, tt.expiresAt)
			if issueErr == nil || token != (Token{}) {
				t.Fatal("invalid input produced an access token")
			}
		})
	}
}

func TestNewIssuerRejectsInvalidConfiguration(t *testing.T) {
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	inconsistent := append(ed25519.PrivateKey{}, private...)
	inconsistent[len(inconsistent)-1] ^= 1
	tests := []struct {
		name  string
		keyID string
		key   ed25519.PrivateKey
	}{
		{
			name:  "empty ID",
			keyID: "",
			key:   private,
		},
		{
			name:  "invalid ID",
			keyID: "current key",
			key:   private,
		},
		{
			name:  "short private key",
			keyID: "current",
			key:   ed25519.PrivateKey("bad"),
		},
		{
			name:  "inconsistent private key",
			keyID: "current",
			key:   inconsistent,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer, newErr := NewIssuer(tt.keyID, tt.key)
			if newErr == nil || issuer != nil {
				t.Fatal("invalid configuration produced an issuer")
			}
		})
	}
}

func TestNewVerifierRejectsInvalidConfiguration(t *testing.T) {
	public, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		keys map[string]ed25519.PublicKey
	}{
		{
			name: "no keys",
			keys: nil,
		},
		{
			name: "empty ID",
			keys: map[string]ed25519.PublicKey{"": public},
		},
		{
			name: "invalid ID",
			keys: map[string]ed25519.PublicKey{"current key": public},
		},
		{
			name: "short public key",
			keys: map[string]ed25519.PublicKey{"current": {1}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier, newErr := NewVerifier(tt.keys)
			if newErr == nil || verifier != nil {
				t.Fatal("invalid configuration produced a verifier")
			}
		})
	}
}

func TestVerifierRejectsUninitializedReceiver(t *testing.T) {
	for _, tt := range []struct {
		name     string
		verifier *Verifier
	}{
		{
			name:     "nil",
			verifier: nil,
		},
		{
			name:     "zero value",
			verifier: new(Verifier),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.verifier.Verify("access-token"); err == nil {
				t.Fatal("uninitialized verifier accepted a token")
			}
		})
	}
}
