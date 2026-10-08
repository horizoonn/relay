//go:build integration

package integration

import (
	"testing"

	"github.com/horizoonn/relay/identity/internal/password"
)

func testPasswordHasher(t *testing.T) *password.Hasher {
	t.Helper()
	hasher, err := password.NewHasher(1)
	if err != nil {
		t.Fatal(err)
	}
	return hasher
}
