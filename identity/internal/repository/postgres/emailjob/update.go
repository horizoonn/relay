package emailjob

import (
	"context"
	"fmt"
	"time"

	"github.com/horizoonn/relay/identity/internal/domain"
	"github.com/horizoonn/relay/identity/internal/usecase/email"
)

func (r *Repository) MarkPrepared(
	ctx context.Context,
	job email.MailJob,
	user domain.User,
) error {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()
	const query = `
		UPDATE identity.email_jobs
		SET prepared_user_id = $3
		WHERE id = $1
		AND lease_token = $2
		AND lease_until > clock_timestamp()
	`
	result, err := r.executor(ctx).Exec(ctx, query, job.ID, job.LeaseToken, user.ID)
	if err != nil {
		return fmt.Errorf("mark email job prepared: %w", err)
	}
	if result.RowsAffected() != 1 {
		return email.ErrLostMailLease
	}
	return nil
}

func (r *Repository) Delete(ctx context.Context, job email.MailJob) error {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()
	const query = `
		DELETE FROM identity.email_jobs
		WHERE id = $1 AND lease_token = $2
	`
	_, err := r.executor(ctx).Exec(ctx, query, job.ID, job.LeaseToken)
	if err != nil {
		return fmt.Errorf("delete email job: %w", err)
	}
	return nil
}

func (r *Repository) Retry(ctx context.Context, job email.MailJob, next time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()
	const query = `
		UPDATE identity.email_jobs
		SET available_at = $3, lease_token = NULL, lease_until = NULL
		WHERE id = $1 AND lease_token = $2
	`
	_, err := r.executor(ctx).Exec(ctx, query, job.ID, job.LeaseToken, next)
	if err != nil {
		return fmt.Errorf("reschedule email job: %w", err)
	}
	return nil
}
