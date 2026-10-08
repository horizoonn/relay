package app

import (
	"crypto/ed25519"
	"fmt"

	"github.com/horizoonn/relay/platform/pkg/security/accessjwt"

	"github.com/horizoonn/relay/content/internal/config"
)

func newAccessVerifier(cfg config.AccessConfig) (*accessjwt.Verifier, error) {
	keys := make(map[string]ed25519.PublicKey, len(cfg.PublicKeyFiles))
	for id, path := range cfg.PublicKeyFiles {
		public, err := accessjwt.LoadPublicKey(path)
		if err != nil {
			return nil, fmt.Errorf("load Content access public key: %w", err)
		}
		keys[id] = public
	}
	return accessjwt.NewVerifier(keys)
}
