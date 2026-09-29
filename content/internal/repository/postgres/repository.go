package repository

import (
	"time"

	platformpostgres "github.com/horizoonn/relay/platform/pkg/postgres"
)

type Repository struct {
	executor         platformpostgres.ExecutorGetter
	operationTimeout time.Duration
}

func NewRepository(
	executor platformpostgres.ExecutorGetter,
	operationTimeout time.Duration,
) *Repository {
	return &Repository{
		executor:         executor,
		operationTimeout: operationTimeout,
	}
}
