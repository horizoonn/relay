package contentv1

import (
	"context"
	"errors"
	"fmt"
	"uuid"

	contentapi "github.com/horizoonn/relay/shared/pkg/openapi/content/v1"

	"github.com/horizoonn/relay/content/internal/auth"
)

type (
	principalKey struct{}
	originKey    struct{}
)

type principal struct {
	ownerID     uuid.UUID
	accessToken string
}

type Security struct {
	auth          auth.Authenticator
	allowedOrigin string
}

func NewSecurity(
	authenticator auth.Authenticator,
	allowedOrigin string,
) *Security {
	return &Security{
		auth:          authenticator,
		allowedOrigin: allowedOrigin,
	}
}

func withRequestOrigin(ctx context.Context, origin string) context.Context {
	return context.WithValue(ctx, originKey{}, origin)
}

var _ contentapi.SecurityHandler = (*Security)(nil)

func (s *Security) HandleAccessCookie(
	ctx context.Context,
	_ contentapi.OperationName,
	token contentapi.AccessCookie,
) (context.Context, error) {
	ownerID, err := s.auth.Introspect(ctx, token.APIKey)
	if err != nil {
		return ctx, identityError(err)
	}
	if ownerID == uuid.Nil() {
		return ctx, auth.ErrUnauthenticated
	}
	return context.WithValue(ctx, principalKey{}, principal{
		ownerID:     ownerID,
		accessToken: token.APIKey,
	}), nil
}

func (s *Security) HandleCsrfHeader(
	ctx context.Context,
	_ contentapi.OperationName,
	token contentapi.CsrfHeader,
) (context.Context, error) {
	p, ok := ctx.Value(principalKey{}).(principal)
	if !ok {
		return ctx, auth.ErrUnauthenticated
	}
	if origin, _ := ctx.Value(originKey{}).(string); origin != s.allowedOrigin {
		return ctx, auth.ErrForbidden
	}
	if err := s.auth.ValidateCSRF(ctx, p.accessToken, token.APIKey); err != nil {
		return ctx, identityError(err)
	}
	return ctx, nil
}

func identityError(err error) error {
	if errors.Is(err, auth.ErrUnauthenticated) || errors.Is(err, auth.ErrForbidden) ||
		errors.Is(err, auth.ErrIdentityUnavailable) {
		return err
	}
	return fmt.Errorf("%w: %w", auth.ErrIdentityUnavailable, err)
}

func PrincipalFromContext(ctx context.Context) (uuid.UUID, error) {
	p, ok := ctx.Value(principalKey{}).(principal)
	if !ok || p.ownerID == uuid.Nil() {
		return uuid.Nil(), auth.ErrUnauthenticated
	}
	return p.ownerID, nil
}
