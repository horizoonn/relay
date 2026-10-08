package password

import (
	"context"
	"errors"
	"time"
)

var ErrBusy = errors.New("password verification capacity exhausted")

type Hasher struct {
	slots chan struct{}
}

func NewHasher(parallel int) (*Hasher, error) {
	if parallel < 1 || parallel > 16 {
		return nil, errors.New("password parallelism must be between 1 and 16")
	}
	return &Hasher{
		slots: make(chan struct{}, parallel),
	}, nil
}

func (h *Hasher) Hash(ctx context.Context, value string) (string, error) {
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer func() { <-h.slots }()
	return Hash(value)
}

func (h *Hasher) Verify(ctx context.Context, value, encoded string) (bool, error) {
	if err := h.acquire(ctx); err != nil {
		return false, err
	}
	defer func() { <-h.slots }()
	return Verify(value, encoded)
}

func (h *Hasher) acquire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-timer.C:
		return ErrBusy
	case h.slots <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-h.slots
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
