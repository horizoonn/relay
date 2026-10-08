package identityv1

import (
	"context"
	"time"

	wireuuid "github.com/google/uuid"
	"github.com/horizoonn/relay/platform/pkg/httpmiddleware"
	identityapi "github.com/horizoonn/relay/shared/pkg/openapi/identity/v1"
)

func (h *Handler) Refresh(
	ctx context.Context,
	params identityapi.RefreshParams,
) (identityapi.RefreshRes, error) {
	refreshToken, _ := params.SecureRelayRefresh.Get()
	csrfToken, _ := params.HostRelayCsrf.Get()
	result, err := h.sessions.Refresh(ctx, refreshToken, csrfToken)
	if err != nil {
		return nil, err
	}
	return &identityapi.LoginSessionHeaders{
		XRequestID: httpmiddleware.RequestID(ctx),
		SetCookie: sessionCookies(
			result.AccessToken,
			result.RefreshToken,
			csrfToken,
			result.AccessExpiresAt,
			result.SessionExpiresAt,
		),
		Response: identityapi.LoginSession{
			UserID:           wireuuid.UUID(result.UserID),
			SessionID:        wireuuid.UUID(result.SessionID),
			AccessExpiresAt:  result.AccessExpiresAt,
			SessionExpiresAt: result.SessionExpiresAt.Truncate(time.Second),
		},
	}, nil
}
