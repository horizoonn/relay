package mailcipher

import (
	"bytes"
	"errors"
	"testing"
)

func TestAuthenticatedEncryption(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	cipher, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	other, err := New(bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("a-private-email-and-one-time-token")
	first, err := cipher.Seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	second, err := cipher.Seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) || bytes.Contains(first, plain) {
		t.Fatal("encryption reused nonce or exposed payload")
	}
	mutated := bytes.Clone(first)
	mutated[len(mutated)-1] ^= 1
	for _, tc := range []struct {
		name    string
		cipher  *Cipher
		payload []byte
		valid   bool
	}{
		{
			name:    "round trip",
			cipher:  cipher,
			payload: first,
			valid:   true,
		},
		{
			name:    "tampered",
			cipher:  cipher,
			payload: mutated,
			valid:   false,
		},
		{
			name:    "wrong key",
			cipher:  other,
			payload: first,
			valid:   false,
		},
		{
			name:    "empty",
			cipher:  cipher,
			payload: nil,
			valid:   false,
		},
		{
			name:    "truncated",
			cipher:  cipher,
			payload: first[:12],
			valid:   false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.cipher.Open(tc.payload)
			if tc.valid {
				if err != nil || !bytes.Equal(got, plain) {
					t.Fatal("round trip failed")
				}
			} else if !errors.Is(err, ErrInvalidPayload) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	for _, size := range []int{0, 1025} {
		if _, err := cipher.Seal(make([]byte, size)); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("size=%d err=%v", size, err)
		}
	}
	if _, err := New(key[:31]); err == nil {
		t.Fatal("short key accepted")
	}
}
