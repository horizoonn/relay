package model

import (
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/horizoonn/relay/identity/internal/domain"
)

type RefreshCredential struct {
	TokenHash  []byte
	SessionID  uuid.UUID
	Generation int64
	CreatedAt  time.Time
	ExpiresAt  time.Time
	UsedAt     pgtype.Timestamptz
}

func (m *RefreshCredential) Scan(row pgx.Row) error {
	return row.Scan(
		&m.TokenHash,
		&m.SessionID,
		&m.Generation,
		&m.CreatedAt,
		&m.ExpiresAt,
		&m.UsedAt,
	)
}

func (m RefreshCredential) ToDomain() (domain.RefreshCredential, error) {
	if len(m.TokenHash) != 32 {
		return domain.RefreshCredential{}, domain.ErrInvalidRefreshCredential
	}
	credential := domain.RefreshCredential{
		SessionID:  m.SessionID,
		Generation: m.Generation,
		CreatedAt:  m.CreatedAt,
		ExpiresAt:  m.ExpiresAt,
	}
	copy(credential.TokenHash[:], m.TokenHash)
	if m.UsedAt.Valid {
		credential.UsedAt = &m.UsedAt.Time
	}
	return credential, nil
}
