package user

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/horizoonn/relay/identity/internal/domain"
	"github.com/horizoonn/relay/identity/internal/repository/postgres/model"
)

func (r *Repository) GetByEmailWithPasswordHash(
	ctx context.Context,
	email string,
) (domain.User, string, error) {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()
	const query = `
		SELECT u.id, u.email, u.email_verified_at, u.state, u.created_at, u.updated_at, p.password_hash
		FROM identity.users u
		JOIN identity.password_credentials p ON p.user_id = u.id
		WHERE u.email = $1
	`
	var stored model.User
	hash, err := stored.ScanWithPasswordHash(r.executor(ctx).QueryRow(ctx, query, email))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.User{}, "", domain.ErrNotFound
	}
	if err != nil {
		return domain.User{}, "", fmt.Errorf("get password credentials: %w", err)
	}
	return stored.ToDomain(), hash, nil
}
