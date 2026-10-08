package app

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/platform/pkg/security/accessjwt"

	"github.com/horizoonn/relay/identity/internal/config"
)

func TestAccessVerifierLoadsCurrentAndPreviousKeys(t *testing.T) {
	_, current, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	previous, oldPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(previous)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "previous.pem")
	if writeErr := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	cfg := config.SigningConfig{
		KeyID:          "current",
		PublicKeyFiles: map[string]string{"previous": path},
	}
	verifier, err := newAccessVerifier(cfg, current)
	if err != nil {
		t.Fatal(err)
	}
	for id, private := range map[string]ed25519.PrivateKey{"current": current, "previous": oldPrivate} {
		t.Run(id, func(t *testing.T) {
			issuer, newErr := accessjwt.NewIssuer(id, private)
			if newErr != nil {
				t.Fatal(newErr)
			}
			token, newErr := issuer.Issue(uuid.NewV7(), uuid.NewV7(), [32]byte{1}, time.Now().Add(time.Hour))
			if newErr != nil {
				t.Fatal(newErr)
			}
			if _, newErr := verifier.Verify(token.Raw); newErr != nil {
				t.Fatal("active key rejected", newErr)
			}
		})
	}
}

func TestAccessVerifierRejectsInvalidPreviousKey(t *testing.T) {
	_, current, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(current.Public())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "empty",
			data: nil,
		},
		{
			name: "malformed PEM",
			data: []byte("invalid key sentinel"),
		},
		{
			name: "private key block",
			data: pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: der,
			}),
		},
		{
			name: "invalid DER",
			data: pem.EncodeToMemory(&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: []byte("sentinel"),
			}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "previous.pem")
			if writeErr := os.WriteFile(path, tt.data, 0o600); writeErr != nil {
				t.Fatal(writeErr)
			}
			cfg := config.SigningConfig{
				KeyID:          "current",
				PublicKeyFiles: map[string]string{"previous": path},
			}
			verifier, verifyErr := newAccessVerifier(cfg, current)
			if verifyErr == nil || verifier != nil || strings.Contains(verifyErr.Error(), "sentinel") {
				t.Fatal("invalid previous key accepted or exposed")
			}
		})
	}
}
