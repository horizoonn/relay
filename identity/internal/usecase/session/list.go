package session

import (
	"context"
	"fmt"
	"time"
	"uuid"
)

type Anchor struct {
	CreatedAt time.Time
	ID        uuid.UUID
}

type ListParams struct {
	Limit int
	After *Anchor
}

func (p ListParams) Validate() error {
	if p.Limit < 1 || p.Limit > 100 ||
		(p.After != nil && (p.After.CreatedAt.IsZero() || p.After.ID == uuid.Nil())) {
		return ErrInvalidQuery
	}
	return nil
}

type Info struct {
	ID              uuid.UUID
	CreatedAt       time.Time
	AuthenticatedAt time.Time
	LastSeenAt      time.Time
	ExpiresAt       time.Time
}

type Page struct {
	Sessions []Info
	Next     *Anchor
}

func (s *Service) ListActive(
	ctx context.Context,
	userID uuid.UUID,
	callerID uuid.UUID,
	params ListParams,
) (Page, error) {
	if err := params.Validate(); err != nil {
		return Page{}, err
	}
	if _, err := s.GetCurrent(ctx, userID, callerID); err != nil {
		return Page{}, err
	}
	page, err := s.sessions.ListActive(ctx, userID, time.Now().UTC(), params)
	if err != nil {
		return Page{}, fmt.Errorf("list active sessions: %w", err)
	}
	return page, nil
}
