package session

import (
	"errors"
)

type Service struct {
	users    UserRepository
	sessions SessionRepository
	tx       Transactor
	issuer   AccessIssuer
}

func NewService(
	users UserRepository,
	sessions SessionRepository,
	tx Transactor,
	issuer AccessIssuer,
) (*Service, error) {
	if users == nil || sessions == nil || tx == nil || issuer == nil {
		return nil, errors.New("session service requires repositories, transactor and issuer")
	}
	return &Service{
		users:    users,
		sessions: sessions,
		tx:       tx,
		issuer:   issuer,
	}, nil
}
