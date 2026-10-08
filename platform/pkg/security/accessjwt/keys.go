package accessjwt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
)

func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	block, err := loadKeyPEM(path, "PUBLIC KEY")
	if err != nil {
		return nil, fmt.Errorf("load access public key: %w", err)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid PKIX access public key")
	}
	public, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("access public key must use Ed25519")
	}
	return public, nil
}

func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	block, err := loadKeyPEM(path, "PRIVATE KEY")
	if err != nil {
		return nil, fmt.Errorf("load access private key: %w", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid PKCS8 access private key")
	}
	private, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("access private key must use Ed25519")
	}
	return private, nil
}

func loadKeyPEM(path, blockType string) (*pem.Block, error) {
	file, err := os.Open(path) //nolint:gosec // Operator-configured path, never a token header or request value.
	if err != nil {
		return nil, fmt.Errorf("open access key file: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 4097))
	closeErr := file.Close()
	if closeErr != nil {
		closeErr = fmt.Errorf("close access key file: %w", closeErr)
	}
	if readErr != nil {
		return nil, errors.Join(fmt.Errorf("read access key file: %w", readErr), closeErr)
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(data) > 4096 {
		return nil, errors.New("access key file exceeds 4096 bytes")
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != blockType || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 ||
		bytes.Count(data, []byte("-----BEGIN ")) != 1 ||
		!bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN "+blockType+"-----")) {
		return nil, errors.New("access key must contain one PEM block of the expected type without headers or trailing data")
	}
	return block, nil
}
