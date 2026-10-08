package password

import (
	"errors"
	"unicode/utf8"
)

const (
	minLength = 15
	maxLength = 128
)

var ErrInvalidPassword = errors.New("password must contain 15 to 128 Unicode characters")

func ValidInput(value string) bool {
	return len(value) <= maxLength*utf8.UTFMax && utf8.ValidString(value) &&
		utf8.RuneCountInString(value) <= maxLength
}

func ValidateNew(value string) error {
	if !ValidInput(value) || utf8.RuneCountInString(value) < minLength {
		return ErrInvalidPassword
	}
	return nil
}
