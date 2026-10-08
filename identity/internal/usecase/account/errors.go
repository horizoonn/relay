package account

import "errors"

var ErrInvalidToken = errors.New("account token is invalid, expired or used")
