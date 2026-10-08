package emailjob

import (
	"context"
	"errors"
	"fmt"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"

	"github.com/horizoonn/relay/identity/internal/domain"
	"github.com/horizoonn/relay/identity/internal/repository/postgres/model"
	"github.com/horizoonn/relay/identity/internal/usecase/email"
)

func (r *Repository) Claim(ctx context.Context, now time.Time) (email.MailJob, error) {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()
	const query = `
		WITH candidate AS (
			SELECT id
			FROM identity.email_jobs
			WHERE available_at <= $1
			AND (lease_until IS NULL OR lease_until <= $1)
			ORDER BY available_at, id
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		UPDATE identity.email_jobs j
		SET lease_token = $2, lease_until = $1 + interval '30 seconds', attempts = j.attempts + 1
		FROM candidate c
		WHERE j.id = c.id
		RETURNING j.id, j.encrypted_payload, j.prepared_user_id,
			j.created_at, j.expires_at, j.lease_token, j.attempts
	`
	var job model.EmailJob
	err := job.Scan(r.executor(ctx).QueryRow(ctx, query, now, uuid.NewV7()))
	if errors.Is(err, pgx.ErrNoRows) {
		return email.MailJob{}, domain.ErrNotFound
	}
	if err != nil {
		return email.MailJob{}, fmt.Errorf("claim email job: %w", err)
	}
	return job.ToMailJob(), nil
}
