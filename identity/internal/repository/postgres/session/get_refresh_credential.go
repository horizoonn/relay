package session

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/horizoonn/relay/identity/internal/domain"
	"github.com/horizoonn/relay/identity/internal/repository/postgres/model"
)

func (r *Repository) GetRefreshCredential(
	ctx context.Context,
	hash [32]byte,
) (domain.RefreshCredential, error) {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()

	const query = `
		SELECT token_hash, session_id, generation, created_at, expires_at, used_at
		FROM identity.refresh_credentials WHERE token_hash = $1
	`

	var stored model.RefreshCredential
	if err := stored.Scan(r.executor(ctx).QueryRow(ctx, query, hash[:])); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.RefreshCredential{}, domain.ErrNotFound
		}
		return domain.RefreshCredential{}, fmt.Errorf("get refresh credential: %w", err)
	}
	credential, err := stored.ToDomain()
	if err != nil {
		return domain.RefreshCredential{}, fmt.Errorf("restore refresh credential: %w", err)
	}
	return credential, nil
}
