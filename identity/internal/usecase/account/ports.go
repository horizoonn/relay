package account

import (
	"context"
	"time"
	"uuid"

	"github.com/horizoonn/relay/identity/internal/domain"
)

type UserRepository interface {
	GetForUpdate(context.Context, uuid.UUID) (domain.User, error)
	UpdatePasswordHash(context.Context, uuid.UUID, string, time.Time) error
	VerifyEmail(context.Context, uuid.UUID, time.Time) error
}

type TokenRepository interface {
	Get(context.Context, [32]byte) (domain.AccountToken, error)
	Consume(context.Context, [32]byte, time.Time) error
	InvalidateResets(context.Context, uuid.UUID, time.Time) error
}

type SessionRepository interface {
	RevokeAll(context.Context, uuid.UUID, time.Time) error
}

type Transactor interface {
	WithinTransaction(context.Context, func(context.Context) error) error
}

type PasswordHasher interface {
	Hash(context.Context, string) (string, error)
}

type ChangeNotifier interface {
	QueuePasswordChanged(context.Context, string) error
}
