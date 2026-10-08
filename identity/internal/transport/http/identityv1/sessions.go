package identityv1

import (
	"context"
	"time"
	"uuid"

	wireuuid "github.com/google/uuid"
	"github.com/horizoonn/relay/platform/pkg/httpmiddleware"
	"github.com/horizoonn/relay/platform/pkg/security/accessjwt"
	identityapi "github.com/horizoonn/relay/shared/pkg/openapi/identity/v1"

	"github.com/horizoonn/relay/identity/internal/usecase/session"
)

func accessFromContext(ctx context.Context) (accessjwt.Access, error) {
	access, ok := ctx.Value(accessKey{}).(accessjwt.Access)
	if !ok {
		return accessjwt.Access{}, session.ErrUnauthenticated
	}
	return access, nil
}

func (h *Handler) ListSessions(
	ctx context.Context,
	params identityapi.ListSessionsParams,
) (identityapi.ListSessionsRes, error) {
	access, err := accessFromContext(ctx)
	if err != nil {
		return nil, err
	}
	limit := 20
	if value, ok := params.Limit.Get(); ok {
		limit = value
	}
	query := session.ListParams{
		Limit: limit,
	}
	if raw, ok := params.Cursor.Get(); ok {
		query.After, err = h.cursors.Decode(raw, access.UserID)
		if err != nil {
			return nil, err
		}
	}
	page, err := h.sessions.ListActive(ctx, access.UserID, access.SessionID, query)
	if err != nil {
		return nil, err
	}
	body := identityapi.SessionPage{
		Sessions: make([]identityapi.SessionInfo, 0, len(page.Sessions)),
	}
	for _, item := range page.Sessions {
		body.Sessions = append(body.Sessions, identityapi.SessionInfo{
			SessionID:       wireuuid.UUID(item.ID),
			CreatedAt:       item.CreatedAt.Truncate(time.Second),
			AuthenticatedAt: item.AuthenticatedAt.Truncate(time.Second),
			LastSeenAt:      item.LastSeenAt.Truncate(time.Second),
			ExpiresAt:       item.ExpiresAt.Truncate(time.Second),
			IsCurrent:       item.ID == access.SessionID,
		})
	}
	if page.Next != nil {
		cursor, encodeErr := h.cursors.Encode(access.UserID, *page.Next)
		if encodeErr != nil {
			return nil, encodeErr
		}
		body.NextCursor = identityapi.NewOptString(cursor)
	}
	return &identityapi.SessionPageHeaders{
		XRequestID: httpmiddleware.RequestID(ctx),
		Response:   body,
	}, nil
}

func (h *Handler) RevokeSession(
	ctx context.Context,
	params identityapi.RevokeSessionParams,
) (identityapi.RevokeSessionRes, error) {
	access, err := accessFromContext(ctx)
	if err != nil {
		return nil, err
	}
	csrf, _ := params.HostRelayCsrf.Get()
	targetID := uuid.UUID(params.SessionID)
	if err := h.sessions.Revoke(ctx, access.UserID, access.SessionID, targetID, csrf); err != nil {
		return nil, err
	}
	response := &identityapi.RevokeSessionNoContent{
		XRequestID: httpmiddleware.RequestID(ctx),
	}
	if targetID == access.SessionID {
		response.SetCookie = clearSessionCookies()
	}
	return response, nil
}

func (h *Handler) RevokeAllSessions(
	ctx context.Context,
	params identityapi.RevokeAllSessionsParams,
) (identityapi.RevokeAllSessionsRes, error) {
	access, err := accessFromContext(ctx)
	if err != nil {
		return nil, err
	}
	csrf, _ := params.HostRelayCsrf.Get()
	if err := h.sessions.RevokeAll(ctx, access.UserID, access.SessionID, csrf); err != nil {
		return nil, err
	}
	return &identityapi.RevokeAllSessionsNoContent{
		XRequestID: httpmiddleware.RequestID(ctx),
		SetCookie:  clearSessionCookies(),
	}, nil
}
