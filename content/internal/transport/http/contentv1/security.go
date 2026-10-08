package contentv1

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"uuid"

	"github.com/horizoonn/relay/platform/pkg/httpmiddleware"
	"github.com/horizoonn/relay/platform/pkg/security/accessjwt"
	contentapi "github.com/horizoonn/relay/shared/pkg/openapi/content/v1"
)

type principalKey struct{}

type browserKey struct{}

type principal struct {
	ownerID  uuid.UUID
	csrfHash [32]byte
}

type AccessVerifier interface {
	Verify(string) (accessjwt.Access, error)
}

type browserRequest struct {
	origin          string
	csrfCookie      string
	originCount     int
	csrfHeaderCount int
}

type Security struct {
	verifier      AccessVerifier
	allowedOrigin string
}

func NewSecurity(
	verifier AccessVerifier,
	allowedOrigin string,
) *Security {
	return &Security{
		verifier:      verifier,
		allowedOrigin: allowedOrigin,
	}
}

func withBrowserRequest(ctx context.Context, request browserRequest) context.Context {
	return context.WithValue(ctx, browserKey{}, request)
}

var _ contentapi.SecurityHandler = (*Security)(nil)

func (s *Security) HandleAccessCookie(
	ctx context.Context,
	operation contentapi.OperationName,
	token contentapi.AccessCookie,
) (context.Context, error) {
	httpmiddleware.SetOperation(ctx, operation)
	access, err := s.verifier.Verify(token.APIKey)
	if err != nil {
		return ctx, errUnauthenticated
	}
	if access.UserID == uuid.Nil() || access.SessionID == uuid.Nil() {
		return ctx, errUnauthenticated
	}
	return context.WithValue(ctx, principalKey{}, principal{
		ownerID:  access.UserID,
		csrfHash: access.CSRFHash,
	}), nil
}

func (s *Security) HandleCsrfHeader(
	ctx context.Context,
	_ contentapi.OperationName,
	token contentapi.CsrfHeader,
) (context.Context, error) {
	p, ok := ctx.Value(principalKey{}).(principal)
	if !ok {
		return ctx, errUnauthenticated
	}
	request, ok := ctx.Value(browserKey{}).(browserRequest)
	if !ok || request.originCount != 1 || request.origin != s.allowedOrigin || request.csrfHeaderCount != 1 ||
		len(token.APIKey) != 43 || subtle.ConstantTimeCompare([]byte(request.csrfCookie), []byte(token.APIKey)) != 1 {
		return ctx, errForbidden
	}
	hash := sha256.Sum256([]byte(token.APIKey))
	if subtle.ConstantTimeCompare(hash[:], p.csrfHash[:]) != 1 {
		return ctx, errForbidden
	}
	return ctx, nil
}

func PrincipalFromContext(ctx context.Context) (uuid.UUID, error) {
	p, ok := ctx.Value(principalKey{}).(principal)
	if !ok || p.ownerID == uuid.Nil() {
		return uuid.Nil(), errUnauthenticated
	}
	return p.ownerID, nil
}
