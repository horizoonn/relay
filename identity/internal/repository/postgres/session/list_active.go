package session

import (
	"context"
	"fmt"
	"time"
	"uuid"

	"github.com/horizoonn/relay/identity/internal/repository/postgres/model"
	sessioncase "github.com/horizoonn/relay/identity/internal/usecase/session"
)

func (r *Repository) ListActive(
	ctx context.Context,
	userID uuid.UUID,
	now time.Time,
	params sessioncase.ListParams,
) (sessioncase.Page, error) {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()

	const query = `
		SELECT id, created_at, authenticated_at, last_seen_at, expires_at
		FROM identity.sessions
		WHERE user_id = $1 AND revoked_at IS NULL AND created_at <= $2 AND expires_at > $2
		    AND ($3::timestamptz IS NULL OR (created_at, id) < ($3, $4))
		ORDER BY created_at DESC, id DESC
		LIMIT $5
	`
	var afterAt any
	afterID := uuid.Nil()
	if params.After != nil {
		afterAt, afterID = params.After.CreatedAt, params.After.ID
	}
	rows, err := r.executor(ctx).Query(ctx, query, userID, now, afterAt, afterID, params.Limit+1)
	if err != nil {
		return sessioncase.Page{}, fmt.Errorf("query active sessions: %w", err)
	}
	defer rows.Close()
	items := make([]sessioncase.Info, 0, params.Limit+1)
	for rows.Next() {
		var stored model.SessionInfo
		if err := stored.Scan(rows); err != nil {
			return sessioncase.Page{}, fmt.Errorf("scan active session: %w", err)
		}
		items = append(items, stored.ToInfo())
	}
	if err := rows.Err(); err != nil {
		return sessioncase.Page{}, fmt.Errorf("iterate active sessions: %w", err)
	}
	page := sessioncase.Page{
		Sessions: items,
	}
	if len(items) > params.Limit {
		page.Sessions = items[:params.Limit]
		last := page.Sessions[len(page.Sessions)-1]
		page.Next = &sessioncase.Anchor{
			CreatedAt: last.CreatedAt,
			ID:        last.ID,
		}
	}
	return page, nil
}
