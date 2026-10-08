package emailjob

import (
	"context"
	"fmt"

	"github.com/horizoonn/relay/identity/internal/usecase/email"
)

func (r *Repository) Create(ctx context.Context, job email.MailJob) error {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()
	const query = `
		INSERT INTO identity.email_jobs (id, encrypted_payload, created_at, expires_at, available_at)
		VALUES ($1, $2, $3, $4, $3)
	`
	_, err := r.executor(ctx).Exec(ctx, query, job.ID, job.EncryptedPayload, job.CreatedAt, job.ExpiresAt)
	if err != nil {
		return fmt.Errorf("create email job: %w", err)
	}
	return nil
}
