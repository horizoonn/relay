package item

import "errors"

var (
	ErrInvalidRequest = errors.New("invalid item request")
	ErrItemNotFound   = errors.New("item not found")
)
