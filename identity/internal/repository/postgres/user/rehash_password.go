package user

import (
	"context"
	"fmt"
	"uuid"

	"github.com/horizoonn/relay/identity/internal/domain"
)

func (r *Repository) RehashPassword(ctx context.Context, id uuid.UUID, hash string) error {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()

	const query = `
		UPDATE identity.password_credentials SET password_hash = $2
		WHERE user_id = $1
	`
	result, err := r.executor(ctx).Exec(ctx, query, id, hash)
	if err != nil {
		return fmt.Errorf("rehash password: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}
