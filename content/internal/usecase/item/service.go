package item

import (
	"time"
)

type Service struct {
	repository Repository
	transactor Transactor
	now        func() time.Time
}

func NewService(repository Repository, transactor Transactor) *Service {
	return &Service{
		repository: repository,
		transactor: transactor,
		now:        time.Now,
	}
}
