package auth

import (
	"context"
	"errors"
	"uuid"
)

var (
	ErrUnauthenticated     = errors.New("unauthenticated")
	ErrForbidden           = errors.New("forbidden")
	ErrIdentityUnavailable = errors.New("identity unavailable")
)

type Authenticator interface {
	Introspect(context.Context, string) (uuid.UUID, error)
	ValidateCSRF(context.Context, string, string) error
}
