package contentv1

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/content/internal/usecase/collection"
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
