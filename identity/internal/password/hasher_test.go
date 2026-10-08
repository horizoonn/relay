package password

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewPasswordPolicy(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
		valid bool
	}{
		{
			name:  "too short",
			value: strings.Repeat("я", 14),
			valid: false,
		},
		{
			name:  "Unicode minimum",
			value: strings.Repeat("я", 15),
			valid: true,
		},
		{
			name:  "spaces and emoji",
			value: "пароль с пробелами 🔐",
			valid: true,
		},
		{
			name:  "maximum",
			value: strings.Repeat("🔐", 128),
			valid: true,
		},
		{
			name:  "too long",
			value: strings.Repeat("a", 129),
			valid: false,
		},
		{
			name:  "invalid UTF-8",
			value: strings.Repeat("a", 15) + "\xff",
			valid: false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateNew(test.value)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%t error=%v", test.valid, err)
			}
			if err != nil && !errors.Is(err, ErrInvalidPassword) {
				t.Fatal(err)
			}
		})
	}
}

func TestPasswordSlotIsReleasedOnVerificationError(t *testing.T) {
	s := &Hasher{
		slots: make(chan struct{}, 1),
	}
	if _, err := s.Verify(t.Context(), "value", "malformed hash"); !errors.Is(err, ErrInvalidHash) {
		t.Fatal(err)
	}
	if len(s.slots) != 0 {
		t.Fatal("failed verification retained an Argon2 slot")
	}
}

func TestPasswordSlotWaitCanBeCanceled(t *testing.T) {
	s := &Hasher{
		slots: make(chan struct{}, 1),
	}
	if err := s.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- s.acquire(ctx) }()
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled request is still waiting for Argon2 slot")
	}
	<-s.slots
	if err := s.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-s.slots

	if err := s.acquire(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(s.slots) != 0 {
		t.Fatal("canceled request retained a password slot")
	}
}

func TestPasswordSlotWaitIsBounded(t *testing.T) {
	s := &Hasher{
		slots: make(chan struct{}, 1),
	}
	s.slots <- struct{}{}
	if err := s.acquire(t.Context()); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	if len(s.slots) != 1 {
		t.Fatal("busy request changed occupied slot")
	}
}
