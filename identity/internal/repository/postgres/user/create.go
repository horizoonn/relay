package user

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/horizoonn/relay/identity/internal/domain"
)

func (r *Repository) Create(
	ctx context.Context,
	user domain.User,
	passwordHash string,
) error {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()

	const query = `
		WITH created AS (
			INSERT INTO identity.users
				(id, email, email_verified_at, state, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6)
			RETURNING id
		)
		INSERT INTO identity.password_credentials (user_id, password_hash, created_at, updated_at)
		SELECT id, $7, $5, $6 FROM created
	`
	_, err := r.executor(ctx).Exec(ctx, query, user.ID, user.Email, user.EmailVerifiedAt,
		string(user.State), user.CreatedAt, user.UpdatedAt, passwordHash)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "users_email_uidx" {
		return domain.ErrEmailAlreadyRegistered
	}
	if err != nil {
		return fmt.Errorf("create user and password credentials: %w", err)
	}
	return nil
}
