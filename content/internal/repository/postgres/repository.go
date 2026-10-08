package repository

import (
	"time"

	"github.com/horizoonn/relay/platform/pkg/postgres"
)

type Repository struct {
	executor         postgres.ExecutorFunc
	operationTimeout time.Duration
}

func NewRepository(
	executor postgres.ExecutorFunc,
	operationTimeout time.Duration,
) *Repository {
	return &Repository{
		executor:         executor,
		operationTimeout: operationTimeout,
	}
}
