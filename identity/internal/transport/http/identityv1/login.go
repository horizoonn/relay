package identityv1

import (
	"context"
	"time"

	wireuuid "github.com/google/uuid"
	"github.com/horizoonn/relay/platform/pkg/httpmiddleware"
	identityapi "github.com/horizoonn/relay/shared/pkg/openapi/identity/v1"
)

func (h *Handler) Login(
	ctx context.Context,
	req *identityapi.Credentials,
	_ identityapi.LoginParams,
) (identityapi.LoginRes, error) {
	result, err := h.auth.Login(ctx, req.Email, req.Password)
	if err != nil {
		return nil, err
	}
	return &identityapi.LoginSessionHeaders{
		XRequestID: httpmiddleware.RequestID(ctx),
		SetCookie: sessionCookies(result.AccessToken, result.RefreshToken, result.CSRFToken,
			result.AccessExpiresAt, result.SessionExpiresAt),
		Response: identityapi.LoginSession{
			UserID:           wireuuid.UUID(result.UserID),
			SessionID:        wireuuid.UUID(result.SessionID),
			AccessExpiresAt:  result.AccessExpiresAt,
			SessionExpiresAt: result.SessionExpiresAt.Truncate(time.Second),
		},
	}, nil
}
