package domain

import (
	"time"
	"uuid"
)

const MaxSessionLifetime = 30 * 24 * time.Hour

type Session struct {
	ID              uuid.UUID
	UserID          uuid.UUID
	CSRFHash        [32]byte
	CreatedAt       time.Time
	AuthenticatedAt time.Time
	LastSeenAt      time.Time
	ExpiresAt       time.Time
	RevokedAt       *time.Time
}

func NewSession(
	userID uuid.UUID,
	csrfHash [32]byte,
	now, expiresAt time.Time,
) (Session, error) {
	s := Session{
		ID:              uuid.NewV7(),
		UserID:          userID,
		CSRFHash:        csrfHash,
		CreatedAt:       now,
		AuthenticatedAt: now,
		LastSeenAt:      now,
		ExpiresAt:       expiresAt,
	}
	return s, s.Validate()
}

func (s Session) Validate() error {
	if s.ID == uuid.Nil() || s.UserID == uuid.Nil() || s.CSRFHash == [32]byte{} ||
		s.CreatedAt.IsZero() || !s.ExpiresAt.After(s.CreatedAt) ||
		s.AuthenticatedAt.Before(s.CreatedAt) || !s.AuthenticatedAt.Before(s.ExpiresAt) ||
		s.LastSeenAt.Before(s.AuthenticatedAt) || !s.LastSeenAt.Before(s.ExpiresAt) ||
		(s.RevokedAt != nil && s.RevokedAt.Before(s.CreatedAt)) {
		return ErrInvalidSession
	}
	return nil
}

func (s Session) Active(now time.Time) bool {
	return !s.CreatedAt.IsZero() && s.RevokedAt == nil &&
		!now.Before(s.CreatedAt) && now.Before(s.ExpiresAt)
}
