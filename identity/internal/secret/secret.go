package secret

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

const size = 32

var ErrInvalid = errors.New("invalid secret")

func Generate() (string, error) {
	var value [size]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}

func Digest(raw string) ([sha256.Size]byte, error) {
	if len(raw) != base64.RawURLEncoding.EncodedLen(size) {
		return [sha256.Size]byte{}, ErrInvalid
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(decoded) != size || base64.RawURLEncoding.EncodeToString(decoded) != raw {
		return [sha256.Size]byte{}, ErrInvalid
	}
	return sha256.Sum256([]byte(raw)), nil
}
