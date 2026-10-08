package session

import (
	"context"
	"time"
	"uuid"

	"github.com/horizoonn/relay/platform/pkg/security/accessjwt"

	"github.com/horizoonn/relay/identity/internal/domain"
)

type UserRepository interface {
	Get(context.Context, uuid.UUID) (domain.User, error)
	GetForUpdate(context.Context, uuid.UUID) (domain.User, error)
}

type SessionRepository interface {
	Get(context.Context, uuid.UUID, uuid.UUID) (domain.Session, error)
	GetByRefreshHash(context.Context, [32]byte) (domain.Session, error)
	GetForUpdate(context.Context, uuid.UUID, uuid.UUID) (domain.Session, error)
	GetRefreshCredential(context.Context, [32]byte) (domain.RefreshCredential, error)
	RotateRefreshCredential(context.Context, [32]byte, domain.RefreshCredential) error
	Revoke(context.Context, uuid.UUID, uuid.UUID, time.Time) error
	RevokeAll(context.Context, uuid.UUID, time.Time) error
	ListActive(context.Context, uuid.UUID, time.Time, ListParams) (Page, error)
}

type Transactor interface {
	WithinTransaction(context.Context, func(context.Context) error) error
}

type AccessIssuer interface {
	Issue(uuid.UUID, uuid.UUID, [32]byte, time.Time) (accessjwt.Token, error)
}
