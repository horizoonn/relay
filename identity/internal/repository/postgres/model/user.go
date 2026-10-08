package model

import (
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/horizoonn/relay/identity/internal/domain"
)

type User struct {
	ID              uuid.UUID
	Email           string
	EmailVerifiedAt pgtype.Timestamptz
	State           string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

func (m *User) Scan(row pgx.Row) error {
	return row.Scan(
		&m.ID,
		&m.Email,
		&m.EmailVerifiedAt,
		&m.State,
		&m.CreatedAt,
		&m.UpdatedAt,
	)
}

func (m *User) ScanWithPasswordHash(row pgx.Row) (string, error) {
	var hash string
	err := row.Scan(
		&m.ID,
		&m.Email,
		&m.EmailVerifiedAt,
		&m.State,
		&m.CreatedAt,
		&m.UpdatedAt,
		&hash,
	)
	return hash, err
}

func (m User) ToDomain() domain.User {
	user := domain.User{
		ID:        m.ID,
		Email:     m.Email,
		State:     domain.UserState(m.State),
		CreatedAt: m.CreatedAt,
		UpdatedAt: m.UpdatedAt,
	}
	if m.EmailVerifiedAt.Valid {
		user.EmailVerifiedAt = &m.EmailVerifiedAt.Time
	}
	return user
}
