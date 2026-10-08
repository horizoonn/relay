package model

import (
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"

	"github.com/horizoonn/relay/identity/internal/usecase/email"
)

type EmailJob struct {
	ID               uuid.UUID
	EncryptedPayload []byte
	PreparedUserID   *uuid.UUID
	CreatedAt        time.Time
	ExpiresAt        time.Time
	LeaseToken       uuid.UUID
	Attempts         int
}

func (m *EmailJob) Scan(row pgx.Row) error {
	return row.Scan(
		&m.ID,
		&m.EncryptedPayload,
		&m.PreparedUserID,
		&m.CreatedAt,
		&m.ExpiresAt,
		&m.LeaseToken,
		&m.Attempts,
	)
}

func (m EmailJob) ToMailJob() email.MailJob {
	job := email.MailJob{
		ID:               m.ID,
		EncryptedPayload: m.EncryptedPayload,
		CreatedAt:        m.CreatedAt,
		ExpiresAt:        m.ExpiresAt,
		LeaseToken:       m.LeaseToken,
		Attempts:         m.Attempts,
	}
	if m.PreparedUserID != nil {
		job.PreparedUserID = *m.PreparedUserID
	}
	return job
}
