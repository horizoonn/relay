package session

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/horizoonn/relay/identity/internal/domain"
	"github.com/horizoonn/relay/identity/internal/repository/postgres/model"
)

func (r *Repository) GetByRefreshHash(ctx context.Context, hash [32]byte) (domain.Session, error) {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()

	const query = `
		SELECT s.id, s.user_id, s.csrf_hash, s.created_at, s.authenticated_at,
			s.last_seen_at, s.expires_at, s.revoked_at
		FROM identity.sessions s
		JOIN identity.refresh_credentials c ON c.session_id = s.id
		WHERE c.token_hash = $1
	`

	var stored model.Session
	if err := stored.Scan(r.executor(ctx).QueryRow(ctx, query, hash[:])); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Session{}, domain.ErrNotFound
		}
		return domain.Session{}, fmt.Errorf("get session by refresh credential: %w", err)
	}
	session, err := stored.ToDomain()
	if err != nil {
		return domain.Session{}, fmt.Errorf("restore refresh session: %w", err)
	}
	return session, nil
}
