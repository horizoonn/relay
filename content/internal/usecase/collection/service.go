package collection

import (
	"errors"
	"fmt"
	"uuid"
)

const maxLimit = 100

var ErrInvalidQuery = errors.New("invalid collection query")

type Service struct {
	reader Reader
}

func NewService(reader Reader) *Service {
	return &Service{
		reader: reader,
	}
}

func validateParams(params ListParams) error {
	if params.OwnerID == uuid.Nil() {
		return fmt.Errorf("%w: missing owner ID", ErrInvalidQuery)
	}
	if params.Limit < 1 || params.Limit > maxLimit {
		return fmt.Errorf("%w: limit must be between 1 and %d", ErrInvalidQuery, maxLimit)
	}
	if params.After != nil && (params.After.At.IsZero() || params.After.ID == uuid.Nil()) {
		return fmt.Errorf("%w: invalid page anchor", ErrInvalidQuery)
	}
	return nil
}
