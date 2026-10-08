package accessjwt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
	"uuid"

	"github.com/golang-jwt/jwt/v5"
)

const (
	issuerName    = "relay-identity"
	audienceName  = "relay-api"
	tokenType     = "relay-at+jwt" //nolint:gosec // Public JWT type discriminator.
	maxLifetime   = 5 * time.Minute
	maxFutureIAT  = 30 * time.Second
	maxTokenBytes = 4096
)

var ErrInvalidToken = errors.New("invalid Relay access token")

type Access struct {
	UserID    uuid.UUID
	SessionID uuid.UUID
	CSRFHash  [32]byte
	ExpiresAt time.Time
}

type Token struct {
	Raw       string
	ExpiresAt time.Time
}

type claims struct {
	jwt.RegisteredClaims
	SessionID string `json:"sid"`
	CSRFHash  string `json:"csrf_hash"`
}

type Issuer struct {
	keyID   string
	private ed25519.PrivateKey
	now     func() time.Time
}

func NewIssuer(keyID string, private ed25519.PrivateKey) (*Issuer, error) {
	if !validKeyID(keyID) {
		return nil, errors.New("invalid signing key ID")
	}
	if len(private) != ed25519.PrivateKeySize ||
		!bytes.Equal(ed25519.NewKeyFromSeed(private[:ed25519.SeedSize]), private) {
		return nil, errors.New("invalid Ed25519 private key")
	}
	return &Issuer{
		keyID:   keyID,
		private: bytes.Clone(private),
		now:     time.Now,
	}, nil
}

func (i *Issuer) Issue(
	userID, sessionID uuid.UUID,
	csrfHash [32]byte,
	sessionExpiresAt time.Time,
) (Token, error) {
	if i == nil || i.now == nil || len(i.private) != ed25519.PrivateKeySize ||
		userID == uuid.Nil() || sessionID == uuid.Nil() || csrfHash == [32]byte{} {
		return Token{}, errors.New("invalid access token input")
	}
	now := i.now().UTC().Truncate(time.Second)
	expiresAt := now.Add(maxLifetime)
	if sessionExpiresAt.Before(expiresAt) {
		expiresAt = sessionExpiresAt
	}
	expiresAt = expiresAt.UTC().Truncate(time.Second)
	if !expiresAt.After(now) {
		return Token{}, errors.New("session has expired")
	}
	data := claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuerName,
			Subject:   userID.String(),
			Audience:  jwt.ClaimStrings{audienceName},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
		SessionID: sessionID.String(),
		CSRFHash:  base64.RawURLEncoding.EncodeToString(csrfHash[:]),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, data)
	token.Header["typ"] = tokenType
	token.Header["kid"] = i.keyID
	raw, err := token.SignedString(i.private)
	if err != nil {
		return Token{}, fmt.Errorf("sign Relay access token: %w", err)
	}
	return Token{
		Raw:       raw,
		ExpiresAt: expiresAt,
	}, nil
}

type Verifier struct {
	keys map[string]ed25519.PublicKey
	now  func() time.Time
}

func NewVerifier(keys map[string]ed25519.PublicKey) (*Verifier, error) {
	if len(keys) == 0 {
		return nil, errors.New("no Relay access verification keys")
	}
	copyKeys := make(map[string]ed25519.PublicKey, len(keys))
	for keyID, public := range keys {
		if !validKeyID(keyID) || len(public) != ed25519.PublicKeySize {
			return nil, errors.New("invalid Relay access verification key")
		}
		copyKeys[keyID] = bytes.Clone(public)
	}
	return &Verifier{
		keys: copyKeys,
		now:  time.Now,
	}, nil
}

func (v *Verifier) Verify(raw string) (Access, error) {
	if v == nil || v.now == nil || len(v.keys) == 0 || raw == "" || len(raw) > maxTokenBytes {
		return Access{}, ErrInvalidToken
	}
	data := new(claims)
	token, err := jwt.ParseWithClaims(raw, data, v.verificationKey,
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithIssuer(issuerName),
		jwt.WithAudience(audienceName),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(v.now),
		jwt.WithStrictDecoding(),
	)
	if err != nil || !token.Valid {
		return Access{}, ErrInvalidToken
	}
	if err = validateClaims(data, v.now().UTC()); err != nil {
		return Access{}, ErrInvalidToken
	}
	return accessFromClaims(data)
}

func (v *Verifier) verificationKey(token *jwt.Token) (any, error) {
	if token.Method.Alg() != jwt.SigningMethodEdDSA.Alg() || token.Header["typ"] != tokenType {
		return nil, ErrInvalidToken
	}
	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, ErrInvalidToken
	}
	public, ok := v.keys[keyID]
	if !ok {
		return nil, ErrInvalidToken
	}
	return public, nil
}

func validateClaims(data *claims, now time.Time) error {
	if data.IssuedAt == nil || data.ExpiresAt == nil || len(data.Audience) != 1 || data.Audience[0] != audienceName {
		return ErrInvalidToken
	}
	if data.IssuedAt.After(now.Add(maxFutureIAT)) ||
		!data.ExpiresAt.After(data.IssuedAt.Time) ||
		data.ExpiresAt.Sub(data.IssuedAt.Time) > maxLifetime {
		return ErrInvalidToken
	}
	return nil
}

func accessFromClaims(data *claims) (Access, error) {
	userID, err := uuid.Parse(data.Subject)
	if err != nil || userID == uuid.Nil() {
		return Access{}, ErrInvalidToken
	}
	sessionID, err := uuid.Parse(data.SessionID)
	if err != nil || sessionID == uuid.Nil() {
		return Access{}, ErrInvalidToken
	}
	decodedHash, err := base64.RawURLEncoding.DecodeString(data.CSRFHash)
	if err != nil || len(decodedHash) != 32 ||
		base64.RawURLEncoding.EncodeToString(decodedHash) != data.CSRFHash {
		return Access{}, ErrInvalidToken
	}
	var csrfHash [32]byte
	copy(csrfHash[:], decodedHash)
	return Access{
		UserID:    userID,
		SessionID: sessionID,
		CSRFHash:  csrfHash,
		ExpiresAt: data.ExpiresAt.Time,
	}, nil
}

func validKeyID(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') &&
			(char < 'A' || char > 'Z') &&
			(char < '0' || char > '9') && char != '-' && char != '_' {
			return false
		}
	}
	return true
}
