package contentv1

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"time"
	"uuid"

	"github.com/horizoonn/relay/content/internal/usecase/collection"
	"github.com/horizoonn/relay/content/internal/usecase/search"
)

var ErrInvalidCursor = errors.New("invalid cursor")

const cursorVersion = 1

type CursorCodec struct {
	key []byte
}

func NewCursorCodec(key []byte) (*CursorCodec, error) {
	if len(key) < 32 {
		return nil, errors.New("cursor signing key must contain at least 32 bytes")
	}
	return &CursorCodec{
		key: append([]byte(nil), key...),
	}, nil
}

type cursorPayload struct {
	Version int              `json:"v"`
	Owner   uuid.UUID        `json:"o"`
	Surface string           `json:"s"`
	Query   [32]byte         `json:"q"`
	At      time.Time        `json:"t"`
	ID      uuid.UUID        `json:"i"`
	Tier    search.MatchTier `json:"r,omitempty"`
}

func (c *CursorCodec) EncodeCollection(
	owner uuid.UUID,
	surface string,
	anchor collection.Anchor,
) (string, error) {
	return c.encode(cursorPayload{
		Version: cursorVersion,
		Owner:   owner,
		Surface: surface,
		At:      anchor.At,
		ID:      anchor.ID,
	})
}

func (c *CursorCodec) DecodeCollection(
	value string,
	owner uuid.UUID,
	surface string,
) (collection.Anchor, error) {
	p, err := c.decode(value)
	if err != nil || p.Version != cursorVersion || p.Owner != owner ||
		p.Surface != surface || p.Tier != 0 || p.Query != ([32]byte{}) {
		return collection.Anchor{}, ErrInvalidCursor
	}
	return collection.Anchor{
		At: p.At,
		ID: p.ID,
	}, nil
}

func (c *CursorCodec) EncodeSearch(
	owner uuid.UUID,
	query string,
	anchor search.Anchor,
) (string, error) {
	return c.encode(cursorPayload{
		Version: cursorVersion,
		Owner:   owner,
		Surface: "search",
		Query:   sha256.Sum256([]byte(query)),
		At:      anchor.LastCapturedAt,
		ID:      anchor.ID,
		Tier:    anchor.Tier,
	})
}

func (c *CursorCodec) DecodeSearch(
	value string,
	owner uuid.UUID,
	query string,
) (search.Anchor, error) {
	p, err := c.decode(value)
	if err != nil || p.Version != cursorVersion || p.Owner != owner ||
		p.Surface != "search" || p.Query != sha256.Sum256([]byte(query)) {
		return search.Anchor{}, ErrInvalidCursor
	}
	return search.Anchor{
		Tier:           p.Tier,
		LastCapturedAt: p.At,
		ID:             p.ID,
	}, nil
}

func (c *CursorCodec) encode(p cursorPayload) (string, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("encode cursor: %w", err)
	}
	mac := hmac.New(sha256.New, c.key)
	_, _ = mac.Write(data)
	return base64.RawURLEncoding.EncodeToString(append(data, mac.Sum(nil)...)), nil
}

func (c *CursorCodec) decode(value string) (cursorPayload, error) {
	if len(value) == 0 || len(value) > 2048 {
		return cursorPayload{}, ErrInvalidCursor
	}
	buf, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(buf) <= sha256.Size {
		return cursorPayload{}, ErrInvalidCursor
	}
	data, signature := buf[:len(buf)-sha256.Size], buf[len(buf)-sha256.Size:]
	mac := hmac.New(sha256.New, c.key)
	_, _ = mac.Write(data)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return cursorPayload{}, ErrInvalidCursor
	}
	var p cursorPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return cursorPayload{}, ErrInvalidCursor
	}
	if p.At.IsZero() || p.ID == uuid.Nil() {
		return cursorPayload{}, ErrInvalidCursor
	}
	return p, nil
}
