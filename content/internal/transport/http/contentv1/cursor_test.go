package contentv1

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/content/internal/usecase/collection"
	"github.com/horizoonn/relay/content/internal/usecase/search"
)

func TestCollectionCursorInvalid(t *testing.T) {
	t.Parallel()
	codec, err := NewCursorCodec([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	owner := uuid.New()
	cursor, err := codec.EncodeCollection(owner, "recent", collection.Anchor{
		At: time.Unix(100, 0),
		ID: uuid.New(),
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		t.Fatal(err)
	}
	data[0] ^= 1
	tampered := base64.RawURLEncoding.EncodeToString(data)
	for _, tt := range []struct {
		name    string
		cursor  string
		owner   uuid.UUID
		surface string
	}{
		{
			name:    "different owner",
			cursor:  cursor,
			owner:   uuid.New(),
			surface: "recent",
		},
		{
			name:    "different surface",
			cursor:  cursor,
			owner:   owner,
			surface: "library",
		},
		{
			name:    "tampered payload",
			cursor:  tampered,
			owner:   owner,
			surface: "recent",
		},
		{
			name:    "malformed encoding",
			cursor:  "!",
			owner:   owner,
			surface: "recent",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := codec.DecodeCollection(tt.cursor, tt.owner, tt.surface); !errors.Is(err, ErrInvalidCursor) {
				t.Fatalf("DecodeCollection() error = %v; want ErrInvalidCursor", err)
			}
		})
	}
}

func TestCursorRoundTripPreservesMicroseconds(t *testing.T) {
	t.Parallel()
	codec, err := NewCursorCodec([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	owner, id := uuid.New(), uuid.New()
	at := time.Date(2026, time.October, 5, 12, 0, 0, 123456000, time.UTC)
	for _, surface := range []string{"recent", "library", "later"} {
		t.Run(surface, func(t *testing.T) {
			t.Parallel()
			anchor := collection.Anchor{At: at, ID: id}
			raw, err := codec.EncodeCollection(owner, surface, anchor)
			if err != nil {
				t.Fatal(err)
			}
			got, err := codec.DecodeCollection(raw, owner, surface)
			if err != nil {
				t.Fatal(err)
			}
			if got.ID != anchor.ID || !got.At.Equal(anchor.At) {
				t.Fatalf("round trip: got=%+v want=%+v", got, anchor)
			}
		})
	}
	t.Run("search", func(t *testing.T) {
		t.Parallel()
		anchor := search.Anchor{Tier: search.MatchTitleExact, LastCapturedAt: at, ID: id}
		raw, err := codec.EncodeSearch(owner, "alpha", anchor)
		if err != nil {
			t.Fatal(err)
		}
		got, err := codec.DecodeSearch(raw, owner, "alpha")
		if err != nil {
			t.Fatal(err)
		}
		if got.Tier != anchor.Tier || got.ID != anchor.ID || !got.LastCapturedAt.Equal(anchor.LastCapturedAt) {
			t.Fatalf("round trip: got=%+v want=%+v", got, anchor)
		}
		if _, err := codec.DecodeSearch(raw, owner, "beta"); !errors.Is(err, ErrInvalidCursor) {
			t.Fatalf("different query error=%v", err)
		}
	})
}
