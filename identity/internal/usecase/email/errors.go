package email

import "errors"

var (
	ErrLostMailLease  = errors.New("email job lease lost")
	ErrInvalidMailJob = errors.New("invalid account email job")
)
