package identityv1

import (
	"context"
	"time"

	wireuuid "github.com/google/uuid"
	"github.com/horizoonn/relay/platform/pkg/httpmiddleware"
	"github.com/horizoonn/relay/platform/pkg/security/accessjwt"
	identityapi "github.com/horizoonn/relay/shared/pkg/openapi/identity/v1"

	identitylimit "github.com/horizoonn/relay/identity/internal/ratelimit"
	"github.com/horizoonn/relay/identity/internal/usecase/session"
)

type accessKey struct{}

func (h *Handler) HandleAccessCookie(
	ctx context.Context,
	operation identityapi.OperationName,
	token identityapi.AccessCookie,
) (context.Context, error) {
	httpmiddleware.SetOperation(ctx, operation)
	access, err := h.verifier.Verify(token.APIKey)
	if err != nil {
		return nil, session.ErrUnauthenticated
	}
	scope := identitylimit.ReadUser
	if operation == identityapi.RevokeSessionOperation || operation == identityapi.RevokeAllSessionsOperation {
		scope = identitylimit.RevokeUser
	}
	if err := h.limiter.Allow(ctx, scope, access.UserID.String()); err != nil {
		return nil, err
	}
	return context.WithValue(ctx, accessKey{}, access), nil
}

func (h *Handler) GetCurrentSession(ctx context.Context) (identityapi.GetCurrentSessionRes, error) {
	access, ok := ctx.Value(accessKey{}).(accessjwt.Access)
	if !ok {
		return nil, session.ErrUnauthenticated
	}
	current, err := h.sessions.GetCurrent(ctx, access.UserID, access.SessionID)
	if err != nil {
		return nil, err
	}
	return &identityapi.CurrentSessionHeaders{
		XRequestID: httpmiddleware.RequestID(ctx),
		Response: identityapi.CurrentSession{
			UserID:           wireuuid.UUID(current.User.ID),
			Email:            current.User.Email,
			EmailVerified:    current.User.EmailVerifiedAt != nil,
			SessionID:        wireuuid.UUID(current.Session.ID),
			AuthenticatedAt:  current.Session.AuthenticatedAt.Truncate(time.Second),
			AccessExpiresAt:  access.ExpiresAt,
			SessionExpiresAt: current.Session.ExpiresAt.Truncate(time.Second),
		},
	}, nil
}
