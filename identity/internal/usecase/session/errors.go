package session

import (
	"errors"

	"github.com/horizoonn/relay/identity/internal/domain"
)

var (
	ErrUnauthenticated = errors.New("authentication required")
	ErrInvalidQuery    = errors.New("invalid session query")
	ErrCSRF            = errors.New("invalid CSRF token")
	ErrSessionNotFound = errors.New("session not found")
	ErrRefreshConflict = errors.New("refresh already used recently")
)

func authenticationError(err error) error {
	if errors.Is(err, domain.ErrNotFound) {
		return ErrUnauthenticated
	}
	return err
}
