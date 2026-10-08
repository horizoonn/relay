package domain

import "errors"

var (
	ErrInvalidEmail             = errors.New("invalid email")
	ErrInvalidUser              = errors.New("invalid user")
	ErrInvalidSession           = errors.New("invalid session")
	ErrInvalidRefreshCredential = errors.New("invalid refresh credential")
	ErrNotFound                 = errors.New("identity record not found")
	ErrEmailAlreadyRegistered   = errors.New("email already registered")
)
