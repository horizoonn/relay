package capture

import (
	"context"
	"time"
	"uuid"

	"github.com/horizoonn/relay/content/internal/domain"
)

type Transactor interface {
	WithinTransaction(
		ctx context.Context,
		fn func(context.Context) error,
	) error
}

type ItemRepository interface {
	FindByNormalizedURL(
		ctx context.Context,
		ownerID uuid.UUID,
		normalizedURL string,
	) (domain.Item, error)

	Create(
		ctx context.Context,
		item domain.Item,
	) (created bool, err error)

	Update(
		ctx context.Context,
		item domain.Item,
	) error
}

type IdempotencyRepository interface {
	Claim(
		ctx context.Context,
		params ClaimParams,
	) (record IdempotencyRecord, claimed bool, err error)

	Complete(
		ctx context.Context,
		params CompleteParams,
	) error
}

type ClaimParams struct {
	OwnerID            uuid.UUID
	Key                string
	FingerprintVersion int16
	Fingerprint        [32]byte
	Now                time.Time
}

type IdempotencyRecord struct {
	FingerprintVersion int16
	Fingerprint        [32]byte
	ItemID             uuid.UUID
	Outcome            Outcome
}

type Outcome string

const (
	OutcomeCreated Outcome = "created"
	OutcomeReused  Outcome = "reused"
)

type CompleteParams struct {
	OwnerID uuid.UUID
	Key     string
	ItemID  uuid.UUID
	Outcome Outcome
}
