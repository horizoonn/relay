package model

import (
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/horizoonn/relay/identity/internal/domain"
)

type Session struct {
	ID              uuid.UUID
	UserID          uuid.UUID
	CSRFHash        []byte
	CreatedAt       time.Time
	AuthenticatedAt time.Time
	LastSeenAt      time.Time
	ExpiresAt       time.Time
	RevokedAt       pgtype.Timestamptz
}

func (m *Session) Scan(row pgx.Row) error {
	return row.Scan(&m.ID, &m.UserID, &m.CSRFHash, &m.CreatedAt,
		&m.AuthenticatedAt, &m.LastSeenAt, &m.ExpiresAt, &m.RevokedAt)
}

func (m Session) ToDomain() (domain.Session, error) {
	if len(m.CSRFHash) != 32 {
		return domain.Session{}, domain.ErrInvalidSession
	}
	session := domain.Session{
		ID:              m.ID,
		UserID:          m.UserID,
		CreatedAt:       m.CreatedAt,
		AuthenticatedAt: m.AuthenticatedAt,
		LastSeenAt:      m.LastSeenAt,
		ExpiresAt:       m.ExpiresAt,
	}
	copy(session.CSRFHash[:], m.CSRFHash)
	if m.RevokedAt.Valid {
		session.RevokedAt = &m.RevokedAt.Time
	}
	return session, nil
}
