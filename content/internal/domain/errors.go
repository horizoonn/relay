package domain

import "errors"

var (
	ErrInvalidItem         = errors.New("invalid item")
	ErrInvalidSource       = errors.New("invalid source")
	ErrInvalidReviewStatus = errors.New("invalid review status")
	ErrInvalidDisplayTitle = errors.New("invalid display title")
)
