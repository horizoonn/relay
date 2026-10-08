package user

import (
	"context"
	"fmt"
	"time"
	"uuid"

	"github.com/horizoonn/relay/identity/internal/domain"
)

func (r *Repository) VerifyEmail(ctx context.Context, id uuid.UUID, now time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()
	const query = `
		UPDATE identity.users
		SET email_verified_at = COALESCE(email_verified_at, GREATEST(created_at, updated_at, $2)),
		    updated_at = GREATEST(created_at, updated_at, $2)
		WHERE id = $1
	`
	result, err := r.executor(ctx).Exec(ctx, query, id, now)
	if err != nil {
		return fmt.Errorf("confirm user email: %w", err)
	}
	if result.RowsAffected() != 1 {
		return domain.ErrNotFound
	}
	return nil
}
