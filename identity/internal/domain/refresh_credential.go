package domain

import (
	"time"
	"uuid"
)

type RefreshCredential struct {
	TokenHash  [32]byte
	SessionID  uuid.UUID
	Generation int64
	CreatedAt  time.Time
	ExpiresAt  time.Time
	UsedAt     *time.Time
}

func (c RefreshCredential) Validate() error {
	if c.TokenHash == [32]byte{} || c.SessionID == uuid.Nil() || c.Generation < 0 ||
		c.CreatedAt.IsZero() || !c.ExpiresAt.After(c.CreatedAt) ||
		(c.UsedAt != nil && (c.UsedAt.Before(c.CreatedAt) || !c.UsedAt.Before(c.ExpiresAt))) {
		return ErrInvalidRefreshCredential
	}
	return nil
}
