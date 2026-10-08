package email

import (
	"context"
	"time"
	"uuid"

	"github.com/horizoonn/relay/identity/internal/domain"
	identitylimit "github.com/horizoonn/relay/identity/internal/ratelimit"
)

type EmailQueue interface {
	Create(context.Context, MailJob) error
}

type PayloadSealer interface {
	Seal([]byte) ([]byte, error)
}

type PayloadOpener interface {
	Open([]byte) ([]byte, error)
}

type RateLimiter interface {
	Allow(context.Context, identitylimit.Scope, string) error
}

type DeliveryUsers interface {
	GetByEmail(context.Context, string) (domain.User, error)
	GetForUpdate(context.Context, uuid.UUID) (domain.User, error)
	GetPasswordUpdatedAt(context.Context, uuid.UUID) (time.Time, error)
}

type DeliveryTokens interface {
	Create(context.Context, domain.AccountToken) error
	Get(context.Context, [32]byte) (domain.AccountToken, error)
}

type MailQueue interface {
	Claim(context.Context, time.Time) (MailJob, error)
	MarkPrepared(context.Context, MailJob, domain.User) error
	Delete(context.Context, MailJob) error
	Retry(context.Context, MailJob, time.Time) error
}

type Sender interface {
	Send(context.Context, Mail) error
}

type Transactor interface {
	WithinTransaction(context.Context, func(context.Context) error) error
}
type DeliveryFailure interface {
	error
	Permanent() bool
}
