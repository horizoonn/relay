package accessjwt

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPublicKey(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	valid := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		data      []byte
		wantError bool
	}{
		{
			name:      "valid",
			data:      valid,
			wantError: false,
		},
		{
			name: "private",
			data: pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: privateDER,
			}),
			wantError: true,
		},
		{
			name:      "trailing data",
			data:      append(append([]byte{}, valid...), []byte("junk")...),
			wantError: true,
		},
		{
			name:      "leading data",
			data:      append([]byte("junk"), valid...),
			wantError: true,
		},
		{
			name:      "two blocks",
			data:      append(append([]byte{}, valid...), valid...),
			wantError: true,
		},
		{
			name:      "oversized",
			data:      make([]byte, 4097),
			wantError: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key.pem")
			if err := os.WriteFile(path, tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := LoadPublicKey(path)
			if (err != nil) != tc.wantError {
				t.Fatalf("key error=%v", err)
			}
			if !tc.wantError && !public.Equal(got) {
				t.Fatal("key changed")
			}
		})
	}
}
