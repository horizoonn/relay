package password

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestHashVerifyAndRehash(t *testing.T) {
	first, err := Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if first == second || strings.Contains(first, "correct horse battery staple") {
		t.Fatal("password hash did not use a fresh salt or exposed the password")
	}
	tests := []struct {
		name      string
		password  string
		wantValid bool
	}{
		{
			name:      "correct password",
			password:  "correct horse battery staple",
			wantValid: true,
		},
		{
			name:     "wrong password",
			password: "wrong password",
		},
		{
			name:     "empty password",
			password: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, verifyErr := Verify(tt.password, first)
			if verifyErr != nil || valid != tt.wantValid {
				t.Fatalf("Verify() = %v, %v; want valid=%v", valid, verifyErr, tt.wantValid)
			}
		})
	}
	needsRehash, err := NeedsRehash(first)
	if err != nil || needsRehash {
		t.Fatalf("current hash: needsRehash=%v err=%v", needsRehash, err)
	}
}

func TestOlderParametersCanBeVerifiedAndRehashed(t *testing.T) {
	salt := []byte("sixteen-byte-salt")
	key := argon2.IDKey([]byte("old password"), salt, 1, 1024, 1, keySize)
	encoded := "$argon2id$v=19$m=1024,t=1,p=1$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(key)
	valid, err := Verify("old password", encoded)
	if err != nil || !valid {
		t.Fatalf("old hash: valid=%v err=%v", valid, err)
	}
	needsRehash, err := NeedsRehash(encoded)
	if err != nil || !needsRehash {
		t.Fatalf("old hash: needsRehash=%v err=%v", needsRehash, err)
	}
}

func TestMalformedHashesFailBeforeArgon2(t *testing.T) {
	salt := base64.RawStdEncoding.EncodeToString([]byte("sixteen-byte-salt"))
	key := base64.RawStdEncoding.EncodeToString(make([]byte, keySize))
	base := "$argon2id$v=19$m=19456,t=2,p=1$" + salt + "$" + key
	tests := []struct {
		name string
		hash string
	}{
		{
			name: "empty",
			hash: "",
		},
		{
			name: "wrong algorithm",
			hash: strings.Replace(base, "argon2id", "argon2i", 1),
		},
		{
			name: "unsupported version",
			hash: strings.Replace(base, "v=19", "v=16", 1),
		},
		{
			name: "excessive memory",
			hash: strings.Replace(base, "m=19456", "m=999999999", 1),
		},
		{
			name: "excessive iterations",
			hash: strings.Replace(base, "t=2", "t=99", 1),
		},
		{
			name: "zero iterations",
			hash: strings.Replace(base, "t=2", "t=0", 1),
		},
		{
			name: "zero parallelism",
			hash: strings.Replace(base, "p=1", "p=0", 1),
		},
		{
			name: "excessive parallelism",
			hash: strings.Replace(base, "p=1", "p=255", 1),
		},
		{
			name: "insufficient memory",
			hash: strings.Replace(base, "m=19456", "m=7", 1),
		},
		{
			name: "invalid salt",
			hash: strings.Replace(base, salt, "!", 1),
		},
		{
			name: "salt with newline",
			hash: strings.Replace(base, salt, salt[:4]+"\n"+salt[4:], 1),
		},
		{
			name: "invalid key",
			hash: strings.Replace(base, key, "!", 1),
		},
		{
			name: "oversized",
			hash: strings.Repeat("x", maxEncodedSize+1),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Verify("password", tt.hash); !errors.Is(err, ErrInvalidHash) {
				t.Errorf("Verify() error = %v, want ErrInvalidHash", err)
			}
			if _, err := NeedsRehash(tt.hash); !errors.Is(err, ErrInvalidHash) {
				t.Errorf("NeedsRehash() error = %v, want ErrInvalidHash", err)
			}
		})
	}
}

func BenchmarkHash(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		if _, err := Hash("correct horse battery staple"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkArgon2Profiles(b *testing.B) {
	for _, profile := range []struct {
		name       string
		memory     uint32
		iterations uint32
	}{
		{
			name:       "19MiB-2",
			memory:     19 * 1024,
			iterations: 2,
		},
		{
			name:       "64MiB-3",
			memory:     64 * 1024,
			iterations: 3,
		},
	} {
		b.Run(profile.name, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				argon2.IDKey([]byte("correct horse battery staple"), []byte("sixteen-byte-salt"),
					profile.iterations, profile.memory, 1, keySize)
			}
		})
	}
}
