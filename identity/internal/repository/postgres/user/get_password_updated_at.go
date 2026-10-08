package user

import (
	"context"
	"errors"
	"fmt"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"

	"github.com/horizoonn/relay/identity/internal/domain"
)

func (r *Repository) GetPasswordUpdatedAt(ctx context.Context, id uuid.UUID) (time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()
	const query = `
		SELECT updated_at
		FROM identity.password_credentials
		WHERE user_id = $1
	`
	var at time.Time
	err := r.executor(ctx).QueryRow(ctx, query, id).Scan(&at)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, domain.ErrNotFound
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("get password change time: %w", err)
	}
	return at, nil
}
