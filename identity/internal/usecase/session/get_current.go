package session

import (
	"context"
	"errors"
	"fmt"
	"time"
	"uuid"

	"github.com/horizoonn/relay/identity/internal/domain"
)

type Current struct {
	User    domain.User
	Session domain.Session
}

func (s *Service) GetCurrent(
	ctx context.Context,
	userID uuid.UUID,
	sessionID uuid.UUID,
) (Current, error) {
	if userID == uuid.Nil() || sessionID == uuid.Nil() {
		return Current{}, ErrUnauthenticated
	}
	current, err := s.getActiveSession(ctx, userID, sessionID)
	if err != nil {
		return Current{}, err
	}
	user, err := s.users.Get(ctx, userID)
	if errors.Is(err, domain.ErrNotFound) {
		return Current{}, ErrUnauthenticated
	}
	if err != nil {
		return Current{}, fmt.Errorf("load current session user: %w", err)
	}
	if err := user.Validate(); err != nil {
		return Current{}, fmt.Errorf("validate current session user: %w", err)
	}
	if user.ID != userID || user.State != domain.UserActive {
		return Current{}, ErrUnauthenticated
	}
	return Current{
		User:    user,
		Session: current,
	}, nil
}

func (s *Service) getActiveSession(
	ctx context.Context,
	userID uuid.UUID,
	sessionID uuid.UUID,
) (domain.Session, error) {
	current, err := s.sessions.Get(ctx, userID, sessionID)
	if errors.Is(err, domain.ErrNotFound) {
		return domain.Session{}, ErrUnauthenticated
	}
	if err != nil {
		return domain.Session{}, fmt.Errorf("load current session: %w", err)
	}
	if validateErr := current.Validate(); validateErr != nil {
		return domain.Session{}, fmt.Errorf("validate current session: %w", validateErr)
	}
	if current.UserID != userID || current.ID != sessionID || !current.Active(time.Now().UTC()) {
		return domain.Session{}, ErrUnauthenticated
	}
	return current, nil
}
