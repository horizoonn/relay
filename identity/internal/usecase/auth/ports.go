package auth

import (
	"context"
	"time"
	"uuid"

	"github.com/horizoonn/relay/platform/pkg/security/accessjwt"

	"github.com/horizoonn/relay/identity/internal/domain"
	identitylimit "github.com/horizoonn/relay/identity/internal/ratelimit"
)

type UserRepository interface {
	Create(context.Context, domain.User, string) error
	GetByEmailWithPasswordHash(context.Context, string) (domain.User, string, error)
	GetForUpdate(context.Context, uuid.UUID) (domain.User, error)
	GetPasswordHash(context.Context, uuid.UUID) (string, error)
	RehashPassword(context.Context, uuid.UUID, string) error
}

type SessionRepository interface {
	Create(context.Context, domain.Session, [32]byte) error
}

type Transactor interface {
	WithinTransaction(context.Context, func(context.Context) error) error
}

type AccessIssuer interface {
	Issue(uuid.UUID, uuid.UUID, [32]byte, time.Time) (accessjwt.Token, error)
}

type RateLimiter interface {
	Allow(context.Context, identitylimit.Scope, string) error
}

type VerificationQueue interface {
	QueueVerification(context.Context, string) error
}

type PasswordHasher interface {
	Hash(context.Context, string) (string, error)
	Verify(context.Context, string, string) (bool, error)
}
