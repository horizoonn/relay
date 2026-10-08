package accounttoken

import (
	"context"
	"fmt"

	"github.com/horizoonn/relay/identity/internal/domain"
)

func (r *Repository) Create(ctx context.Context, token domain.AccountToken) error {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()
	const query = `
		INSERT INTO identity.account_tokens (token_hash, user_id, purpose, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (token_hash) DO NOTHING
	`
	_, err := r.executor(ctx).Exec(ctx,
		query,
		token.Hash[:],
		token.UserID,
		string(token.Purpose),
		token.CreatedAt,
		token.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("create account token: %w", err)
	}
	return nil
}
