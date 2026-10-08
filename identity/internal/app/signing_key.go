package app

import (
	"crypto/ed25519"
	"fmt"

	"github.com/horizoonn/relay/platform/pkg/security/accessjwt"

	"github.com/horizoonn/relay/identity/internal/config"
)

func newAccessVerifier(cfg config.SigningConfig, private ed25519.PrivateKey) (*accessjwt.Verifier, error) {
	keys := map[string]ed25519.PublicKey{cfg.KeyID: private.Public().(ed25519.PublicKey)}
	for keyID, path := range cfg.PublicKeyFiles {
		public, err := accessjwt.LoadPublicKey(path)
		if err != nil {
			return nil, fmt.Errorf("load previous access public key: %w", err)
		}
		keys[keyID] = public
	}
	return accessjwt.NewVerifier(keys)
}
