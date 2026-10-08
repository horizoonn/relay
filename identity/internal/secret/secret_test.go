package secret

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

func TestGenerateAndDigest(t *testing.T) {
	first, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	second, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("two generated secrets are identical")
	}
	for _, raw := range []string{first, second} {
		digest, err := Digest(raw)
		if err != nil {
			t.Fatal(err)
		}
		if digest != sha256.Sum256([]byte(raw)) {
			t.Fatal("digest does not match generated secret")
		}
	}
}

func TestDigestRejectsMalformedSecrets(t *testing.T) {
	tests := []struct {
		name   string
		secret string
	}{
		{
			name:   "empty",
			secret: "",
		},
		{
			name:   "too short",
			secret: "short",
		},
		{
			name:   "too long",
			secret: strings.Repeat("a", 44),
		},
		{
			name:   "invalid alphabet",
			secret: strings.Repeat("!", 43),
		},
		{
			name:   "noncanonical encoding",
			secret: strings.Repeat("_", 43),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Digest(tt.secret); !errors.Is(err, ErrInvalid) {
				t.Errorf("Digest() error = %v, want ErrInvalid", err)
			}
		})
	}
}
