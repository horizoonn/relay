package user

import (
	"context"
	"fmt"
	"time"
	"uuid"

	"github.com/horizoonn/relay/identity/internal/domain"
)

func (r *Repository) UpdatePasswordHash(
	ctx context.Context,
	id uuid.UUID,
	hash string,
	now time.Time,
) error {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()

	const query = `
		UPDATE identity.password_credentials SET password_hash = $2, updated_at = $3
		WHERE user_id = $1
	`
	result, err := r.executor(ctx).Exec(ctx, query, id, hash, now)
	if err != nil {
		return fmt.Errorf("update password hash: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}
