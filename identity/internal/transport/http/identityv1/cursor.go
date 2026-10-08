package identityv1

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"time"
	"uuid"

	"github.com/horizoonn/relay/identity/internal/usecase/session"
)

const sessionCursorVersion = 1

type CursorCodec struct {
	key []byte
}

type cursorPayload struct {
	Version   int       `json:"v"`
	Owner     uuid.UUID `json:"o"`
	CreatedAt time.Time `json:"t"`
	ID        uuid.UUID `json:"i"`
}

func NewCursorCodec(key []byte) (*CursorCodec, error) {
	if len(key) < 32 {
		return nil, errors.New("session cursor signing key must contain at least 32 bytes")
	}
	return &CursorCodec{
		key: append([]byte(nil), key...),
	}, nil
}

func (c *CursorCodec) Encode(owner uuid.UUID, anchor session.Anchor) (string, error) {
	data, err := json.Marshal(cursorPayload{
		Version:   sessionCursorVersion,
		Owner:     owner,
		CreatedAt: anchor.CreatedAt,
		ID:        anchor.ID,
	})
	if err != nil {
		return "", fmt.Errorf("encode session cursor: %w", err)
	}
	mac := hmac.New(sha256.New, c.key)
	_, _ = mac.Write(data)
	return base64.RawURLEncoding.EncodeToString(append(data, mac.Sum(nil)...)), nil
}

func (c *CursorCodec) Decode(raw string, owner uuid.UUID) (*session.Anchor, error) {
	if raw == "" || len(raw) > 2048 {
		return nil, session.ErrInvalidQuery
	}
	buf, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(buf) <= sha256.Size {
		return nil, session.ErrInvalidQuery
	}
	data, signature := buf[:len(buf)-sha256.Size], buf[len(buf)-sha256.Size:]
	mac := hmac.New(sha256.New, c.key)
	_, _ = mac.Write(data)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return nil, session.ErrInvalidQuery
	}
	var payload cursorPayload
	if err := json.Unmarshal(data, &payload); err != nil ||
		payload.Version != sessionCursorVersion ||
		payload.Owner != owner ||
		payload.CreatedAt.IsZero() || payload.ID == uuid.Nil() {
		return nil, session.ErrInvalidQuery
	}
	return &session.Anchor{
		CreatedAt: payload.CreatedAt,
		ID:        payload.ID,
	}, nil
}
