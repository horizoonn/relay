package identityv1

import (
	"context"

	"github.com/horizoonn/relay/platform/pkg/httpmiddleware"
	identityapi "github.com/horizoonn/relay/shared/pkg/openapi/identity/v1"
)

func (h *Handler) Logout(
	ctx context.Context,
	params identityapi.LogoutParams,
) (identityapi.LogoutRes, error) {
	refreshToken, _ := params.SecureRelayRefresh.Get()
	csrfToken, _ := params.HostRelayCsrf.Get()
	if err := h.sessions.Logout(ctx, refreshToken, csrfToken); err != nil {
		return nil, err
	}
	return &identityapi.LogoutNoContent{
		XRequestID: httpmiddleware.RequestID(ctx),
		SetCookie:  clearSessionCookies(),
	}, nil
}
