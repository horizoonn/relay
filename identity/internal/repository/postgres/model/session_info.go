package model

import (
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"

	sessioncase "github.com/horizoonn/relay/identity/internal/usecase/session"
)

type SessionInfo struct {
	ID              uuid.UUID
	CreatedAt       time.Time
	AuthenticatedAt time.Time
	LastSeenAt      time.Time
	ExpiresAt       time.Time
}

func (m *SessionInfo) Scan(row pgx.Row) error {
	return row.Scan(&m.ID, &m.CreatedAt, &m.AuthenticatedAt, &m.LastSeenAt, &m.ExpiresAt)
}

func (m SessionInfo) ToInfo() sessioncase.Info {
	return sessioncase.Info{
		ID:              m.ID,
		CreatedAt:       m.CreatedAt,
		AuthenticatedAt: m.AuthenticatedAt,
		LastSeenAt:      m.LastSeenAt,
		ExpiresAt:       m.ExpiresAt,
	}
}
