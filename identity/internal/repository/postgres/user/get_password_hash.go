package user

import (
	"context"
	"errors"
	"fmt"
	"uuid"

	"github.com/jackc/pgx/v5"

	"github.com/horizoonn/relay/identity/internal/domain"
)

func (r *Repository) GetPasswordHash(ctx context.Context, id uuid.UUID) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()

	const query = `SELECT password_hash FROM identity.password_credentials WHERE user_id = $1`
	var hash string
	err := r.executor(ctx).QueryRow(ctx, query, id).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", domain.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("get password hash: %w", err)
	}
	return hash, nil
}
