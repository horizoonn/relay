package capture

import "errors"

var (
	ErrInvalidCommand       = errors.New("invalid capture command")
	ErrIdempotencyKeyReused = errors.New("idempotency key reused")
	ErrURLHashCollision     = errors.New("URL hash collision")
	ErrURLItemNotFound      = errors.New("URL item not found")
)
