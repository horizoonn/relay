package capture

import (
	"time"
	"uuid"

	"github.com/horizoonn/relay/content/internal/domain"
)

type Command struct {
	OwnerID        uuid.UUID
	IdempotencyKey string
	SourceType     domain.SourceType
	URL            string
	Text           string
	Keep           bool
	Later          bool
}

type Result struct {
	ItemID  uuid.UUID
	Outcome Outcome
}

type Service struct {
	items       ItemRepository
	idempotency IdempotencyRepository
	transactor  Transactor
	now         func() time.Time
	newID       func() uuid.UUID
}

func NewService(
	items ItemRepository,
	idempotency IdempotencyRepository,
	transactor Transactor,
) *Service {
	return &Service{
		items:       items,
		idempotency: idempotency,
		transactor:  transactor,
		now:         time.Now,
		newID:       uuid.New,
	}
}
