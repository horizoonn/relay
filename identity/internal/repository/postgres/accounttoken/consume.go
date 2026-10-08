package accounttoken

import (
	"context"
	"fmt"
	"time"
	"uuid"

	"github.com/horizoonn/relay/identity/internal/domain"
)

func (r *Repository) Consume(
	ctx context.Context,
	hash [32]byte,
	now time.Time,
) error {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()
	const query = `
		UPDATE identity.account_tokens
		SET used_at = $2
		WHERE token_hash = $1
		AND used_at IS NULL
		AND created_at <= $2
		AND expires_at > $2
	`
	result, err := r.executor(ctx).Exec(ctx, query, hash[:], now)
	if err != nil {
		return fmt.Errorf("mark account token used: %w", err)
	}
	if result.RowsAffected() != 1 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *Repository) InvalidateResets(
	ctx context.Context,
	id uuid.UUID,
	now time.Time,
) error {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()
	const query = `
		UPDATE identity.account_tokens
		SET used_at = $2
		WHERE user_id = $1
		AND purpose = 'reset_password'
		AND used_at IS NULL
	`
	_, err := r.executor(ctx).Exec(ctx, query, id, now)
	if err != nil {
		return fmt.Errorf("mark password reset tokens used: %w", err)
	}
	return nil
}

func (r *Repository) DeleteExpired(
	ctx context.Context,
	before time.Time,
	limit int,
) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()
	const query = `
		WITH expired AS (
			SELECT token_hash
			FROM identity.account_tokens
			WHERE expires_at <= $1
			ORDER BY expires_at, token_hash
			FOR UPDATE SKIP LOCKED
			LIMIT $2
		)
		DELETE FROM identity.account_tokens t
		USING expired e
		WHERE t.token_hash = e.token_hash
	`
	result, err := r.executor(ctx).Exec(ctx, query, before, limit)
	if err != nil {
		return 0, fmt.Errorf("delete expired account tokens: %w", err)
	}
	return result.RowsAffected(), nil
}
