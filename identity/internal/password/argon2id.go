package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	memoryKiB   uint32 = 64 * 1024
	iterations  uint32 = 3
	parallelism uint8  = 1
	saltSize           = 16
	keySize            = 32

	maxEncodedSize  = 512
	maxMemoryKiB    = 128 * 1024
	maxIterations   = 6
	maxParallelism  = 4
	minStoredLength = 16
	maxStoredLength = 64
)

var ErrInvalidHash = errors.New("invalid password hash")

type parsedHash struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	salt        []byte
	key         []byte
}

func Hash(value string) (string, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	key := argon2.IDKey([]byte(value), salt, iterations, memoryKiB, parallelism, keySize)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memoryKiB, iterations, parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

func Verify(value, encoded string) (bool, error) {
	stored, err := parse(encoded)
	if err != nil {
		return false, err
	}
	key := argon2.IDKey([]byte(value), stored.salt, stored.iterations,
		stored.memory, stored.parallelism, uint32(len(stored.key))) //nolint:gosec // parse bounds key length to 16..64 bytes.
	return subtle.ConstantTimeCompare(key, stored.key) == 1, nil
}

func NeedsRehash(encoded string) (bool, error) {
	stored, err := parse(encoded)
	if err != nil {
		return false, err
	}
	return stored.memory != memoryKiB || stored.iterations != iterations ||
		stored.parallelism != parallelism || len(stored.salt) != saltSize ||
		len(stored.key) != keySize, nil
}

func parse(encoded string) (parsedHash, error) {
	if len(encoded) > maxEncodedSize {
		return parsedHash{}, ErrInvalidHash
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" ||
		parts[1] != "argon2id" || parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return parsedHash{}, ErrInvalidHash
	}
	stored, err := parseParams(parts[3])
	if err != nil {
		return parsedHash{}, err
	}
	salt, err := decodeHashPart(parts[4])
	if err != nil {
		return parsedHash{}, err
	}
	key, err := decodeHashPart(parts[5])
	if err != nil {
		return parsedHash{}, err
	}
	stored.salt, stored.key = salt, key
	return stored, nil
}

func parseParams(encoded string) (parsedHash, error) {
	fields := strings.Split(encoded, ",")
	if len(fields) != 3 {
		return parsedHash{}, ErrInvalidHash
	}
	memory, ok := parseField(fields[0], "m=", 32)
	if !ok || memory > maxMemoryKiB {
		return parsedHash{}, ErrInvalidHash
	}
	timeCost, ok := parseField(fields[1], "t=", 32)
	if !ok || timeCost == 0 || timeCost > maxIterations {
		return parsedHash{}, ErrInvalidHash
	}
	threads, ok := parseField(fields[2], "p=", 8)
	if !ok || threads == 0 || threads > maxParallelism || memory < 8*threads {
		return parsedHash{}, ErrInvalidHash
	}
	return parsedHash{
		memory:      uint32(memory),
		iterations:  uint32(timeCost),
		parallelism: uint8(threads),
	}, nil
}

func decodeHashPart(encoded string) ([]byte, error) {
	value, err := base64.RawStdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(value) < minStoredLength || len(value) > maxStoredLength ||
		base64.RawStdEncoding.EncodeToString(value) != encoded {
		return nil, ErrInvalidHash
	}
	return value, nil
}

func parseField(value, prefix string, bits int) (uint64, bool) {
	if !strings.HasPrefix(value, prefix) {
		return 0, false
	}
	parsed, err := strconv.ParseUint(strings.TrimPrefix(value, prefix), 10, bits)
	return parsed, err == nil
}
