package accessjwt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPrivateKey(t *testing.T) {
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, err := x509.MarshalPKCS8PrivateKey(other)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		data  []byte
		valid bool
	}{
		{
			name:  "valid",
			data:  encoded,
			valid: true,
		},
		{
			name:  "whitespace",
			data:  append([]byte("\n"), append(bytes.Clone(encoded), '\n')...),
			valid: true,
		},
		{
			name:  "empty",
			data:  nil,
			valid: false,
		},
		{
			name:  "oversized",
			data:  bytes.Repeat([]byte("x"), 4097),
			valid: false,
		},
		{
			name:  "malformed",
			data:  []byte("private key sentinel"),
			valid: false,
		},
		{
			name: "wrong algorithm",
			data: pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: otherDER,
			}),
			valid: false,
		},
		{
			name: "invalid DER",
			data: pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: []byte("sentinel"),
			}),
			valid: false,
		},
		{
			name: "public key block",
			data: pem.EncodeToMemory(&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: der,
			}),
			valid: false,
		},
		{
			name: "PEM headers",
			data: pem.EncodeToMemory(&pem.Block{
				Type:    "PRIVATE KEY",
				Bytes:   der,
				Headers: map[string]string{"X": "sentinel"},
			}),
			valid: false,
		},
		{
			name:  "extra block",
			data:  append(bytes.Clone(encoded), encoded...),
			valid: false,
		},
		{
			name:  "trailing data",
			data:  append(bytes.Clone(encoded), []byte("sentinel")...),
			valid: false,
		},
		{
			name:  "leading data",
			data:  append([]byte("sentinel\n"), encoded...),
			valid: false,
		},
		{
			name:  "malformed leading block",
			data:  append([]byte("-----BEGIN PRIVATE KEY-----\n!!!\n-----END PRIVATE KEY-----\n"), encoded...),
			valid: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key.pem")
			if err := os.WriteFile(path, tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
			key, err := LoadPrivateKey(path)
			if tc.valid {
				if err != nil || !bytes.Equal(key, private) {
					t.Fatal("correct key was not loaded", err)
				}
			} else if err == nil || key != nil || strings.Contains(err.Error(), "sentinel") {
				t.Fatal("invalid key accepted or contents exposed")
			}
		})
	}
	if _, err := LoadPrivateKey(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Fatal("missing key accepted")
	}
}
