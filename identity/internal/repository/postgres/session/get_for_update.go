package session

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
	userID, sessionID uuid.UUID,
) (domain.Session, error) {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()

	const query = `
		SELECT id, user_id, csrf_hash, created_at, authenticated_at, last_seen_at, expires_at, revoked_at
		FROM identity.sessions WHERE user_id = $1 AND id = $2 FOR UPDATE
	`

	var stored model.Session
	if err := stored.Scan(r.executor(ctx).QueryRow(ctx, query, userID, sessionID)); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Session{}, domain.ErrNotFound
		}
		return domain.Session{}, fmt.Errorf("lock session: %w", err)
	}
	session, err := stored.ToDomain()
	if err != nil {
		return domain.Session{}, fmt.Errorf("restore locked session: %w", err)
	}
	return session, nil
}
