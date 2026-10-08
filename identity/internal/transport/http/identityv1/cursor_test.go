package identityv1

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/identity/internal/usecase/session"
)

func TestSessionCursor(t *testing.T) {
	t.Parallel()
	codec := testCursors(t)
	owner := uuid.NewV7()
	anchor := session.Anchor{
		ID:        uuid.NewV7(),
		CreatedAt: time.Date(2026, time.October, 2, 12, 0, 0, 123456000, time.UTC),
	}
	raw, err := codec.Encode(owner, anchor)
	if err != nil {
		t.Fatal(err)
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	data[0] ^= 1
	modified := base64.RawURLEncoding.EncodeToString(data)
	tests := []struct {
		name  string
		raw   string
		owner uuid.UUID
		valid bool
	}{
		{
			name:  "round trip with subsecond timestamp",
			raw:   raw,
			owner: owner,
			valid: true,
		},
		{
			name:  "different owner",
			raw:   raw,
			owner: uuid.NewV7(),
			valid: false,
		},
		{
			name:  "modified payload",
			raw:   modified,
			owner: owner,
			valid: false,
		},
		{
			name:  "empty",
			raw:   "",
			owner: owner,
			valid: false,
		},
		{
			name:  "invalid base64",
			raw:   "!",
			owner: owner,
			valid: false,
		},
		{
			name:  "short",
			raw:   "YWJj",
			owner: owner,
			valid: false,
		},
		{
			name:  "oversized",
			raw:   strings.Repeat("a", 2049),
			owner: owner,
			valid: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			decoded, decodeErr := codec.Decode(tt.raw, tt.owner)
			if tt.valid {
				if decodeErr != nil || decoded.ID != anchor.ID || !decoded.CreatedAt.Equal(anchor.CreatedAt) {
					t.Fatal("cursor lost its anchor", decodeErr)
				}
			} else if decodeErr == nil || decoded != nil {
				t.Fatal("invalid cursor accepted")
			}
		})
	}
}

func TestNewSessionCursorCodec(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name  string
		size  int
		valid bool
	}{
		{
			name:  "empty",
			size:  0,
			valid: false,
		}, {
			name:  "short",
			size:  31,
			valid: false,
		}, {
			name:  "minimum",
			size:  32,
			valid: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			key := []byte(strings.Repeat("k", tt.size))
			codec, err := NewCursorCodec(key)
			if !tt.valid {
				if err == nil || codec != nil {
					t.Fatal("invalid key accepted")
				}
				return
			}
			anchor := session.Anchor{
				ID:        uuid.NewV7(),
				CreatedAt: time.Now(),
			}
			owner := uuid.NewV7()
			raw, err := codec.Encode(owner, anchor)
			if err != nil {
				t.Fatal(err)
			}
			key[0] ^= 1
			if _, err := codec.Decode(raw, owner); err != nil {
				t.Fatal("caller mutated the codec key", err)
			}
		})
	}
}
