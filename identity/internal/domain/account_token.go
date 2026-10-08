package domain

import (
	"errors"
	"time"
	"uuid"
)

type AccountTokenPurpose string

const (
	VerifyEmail   AccountTokenPurpose = "verify_email"
	ResetPassword AccountTokenPurpose = "reset_password"
)

var ErrInvalidAccountToken = errors.New("invalid account token")

func (p AccountTokenPurpose) Lifetime() time.Duration {
	switch p {
	case VerifyEmail:
		return time.Hour
	case ResetPassword:
		return 15 * time.Minute
	default:
		return 0
	}
}

type AccountToken struct {
	Hash      [32]byte
	UserID    uuid.UUID
	Purpose   AccountTokenPurpose
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time
}

func (t AccountToken) Validate() error {
	if t.Hash == [32]byte{} || t.UserID == uuid.Nil() || t.Purpose.Lifetime() == 0 {
		return ErrInvalidAccountToken
	}
	if t.CreatedAt.IsZero() || !t.ExpiresAt.After(t.CreatedAt) ||
		t.ExpiresAt.Sub(t.CreatedAt) > t.Purpose.Lifetime() {
		return ErrInvalidAccountToken
	}
	if t.UsedAt != nil && t.UsedAt.Before(t.CreatedAt) {
		return ErrInvalidAccountToken
	}
	return nil
}

func (t AccountToken) Active(now time.Time) bool {
	return t.UsedAt == nil && !now.Before(t.CreatedAt) && now.Before(t.ExpiresAt)
}
