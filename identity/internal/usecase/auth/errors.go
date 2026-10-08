package auth

import "errors"

var (
	ErrEmailNotVerified   = errors.New("email confirmation required")
	ErrInvalidCredentials = errors.New("invalid email or password")
)
