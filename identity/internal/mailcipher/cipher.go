package mailcipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

var ErrInvalidPayload = errors.New("invalid encrypted Identity email payload")

type Cipher struct {
	aead cipher.AEAD
}

func New(key []byte) (*Cipher, error) {
	if len(key) < 32 {
		return nil, errors.New("email encryption key requires at least 32 bytes")
	}
	digest := sha256.Sum256(key)
	block, err := aes.NewCipher(digest[:])
	if err != nil {
		return nil, fmt.Errorf("initialize email cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize email AEAD: %w", err)
	}
	return &Cipher{
		aead: aead,
	}, nil
}

func (c *Cipher) Seal(value []byte) ([]byte, error) {
	if len(value) == 0 || len(value) > 1024 {
		return nil, ErrInvalidPayload
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate email nonce: %w", err)
	}
	return c.aead.Seal(nonce, nonce, value, []byte("identity-email:v1")), nil
}

func (c *Cipher) Open(value []byte) ([]byte, error) {
	n := c.aead.NonceSize()
	if len(value) <= n || len(value) > 2048 {
		return nil, ErrInvalidPayload
	}
	plain, err := c.aead.Open(nil, value[:n], value[n:], []byte("identity-email:v1"))
	if err != nil {
		return nil, ErrInvalidPayload
	}
	return plain, nil
}
