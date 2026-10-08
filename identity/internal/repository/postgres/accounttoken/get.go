package accounttoken

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/horizoonn/relay/identity/internal/domain"
)

func (r *Repository) Get(ctx context.Context, hash [32]byte) (domain.AccountToken, error) {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()
	const query = `
		SELECT user_id, purpose, created_at, expires_at, used_at
		FROM identity.account_tokens WHERE token_hash = $1
	`
	token := domain.AccountToken{
		Hash: hash,
	}
	err := r.executor(ctx).QueryRow(ctx, query, hash[:]).Scan(
		&token.UserID,
		&token.Purpose,
		&token.CreatedAt,
		&token.ExpiresAt,
		&token.UsedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.AccountToken{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.AccountToken{}, fmt.Errorf("get account token: %w", err)
	}
	return token, nil
}
