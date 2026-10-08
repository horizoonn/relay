package user

import (
	"context"
	"errors"
	"fmt"
	"uuid"

	"github.com/jackc/pgx/v5"

	"github.com/horizoonn/relay/identity/internal/domain"
	"github.com/horizoonn/relay/identity/internal/repository/postgres/model"
)

func (r *Repository) GetForUpdate(
	ctx context.Context,
	id uuid.UUID,
) (domain.User, error) {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()

	const query = `
		SELECT id, email, email_verified_at, state, created_at, updated_at
		FROM identity.users WHERE id = $1 FOR UPDATE
	`

	var stored model.User
	if err := stored.Scan(r.executor(ctx).QueryRow(ctx, query, id)); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.User{}, domain.ErrNotFound
		}
		return domain.User{}, fmt.Errorf("lock user: %w", err)
	}
	return stored.ToDomain(), nil
}
