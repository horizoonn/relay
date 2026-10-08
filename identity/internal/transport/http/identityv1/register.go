package identityv1

import (
	"context"

	wireuuid "github.com/google/uuid"
	"github.com/horizoonn/relay/platform/pkg/httpmiddleware"
	identityapi "github.com/horizoonn/relay/shared/pkg/openapi/identity/v1"
)

func (h *Handler) Register(
	ctx context.Context,
	req *identityapi.Credentials,
	_ identityapi.RegisterParams,
) (identityapi.RegisterRes, error) {
	id, err := h.auth.Register(ctx, req.Email, req.Password)
	if err != nil {
		return nil, err
	}
	return &identityapi.RegisteredUserHeaders{
		XRequestID: httpmiddleware.RequestID(ctx),
		Response: identityapi.RegisteredUser{
			UserID: wireuuid.UUID(id),
		},
	}, nil
}
