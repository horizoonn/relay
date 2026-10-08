package domain

import (
	"errors"
	"testing"
	"time"
	"uuid"
)

func TestAccountTokenLifetimeAndState(t *testing.T) {
	now := time.Now().UTC()
	valid := AccountToken{
		Hash:      [32]byte{1},
		UserID:    uuid.NewV7(),
		Purpose:   VerifyEmail,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}
	for _, tc := range []struct {
		name   string
		change func(*AccountToken)
		want   error
	}{
		{
			name: "verification",
			change: func(*AccountToken) {
			},
			want: nil,
		},
		{
			name: "reset",
			change: func(v *AccountToken) {
				v.Purpose = ResetPassword
				v.ExpiresAt = now.Add(15 * time.Minute)
			},
			want: nil,
		},
		{
			name: "missing hash",
			change: func(v *AccountToken) {
				v.Hash = [32]byte{}
			},
			want: ErrInvalidAccountToken,
		},
		{
			name: "missing owner",
			change: func(v *AccountToken) {
				v.UserID = uuid.Nil()
			},
			want: ErrInvalidAccountToken,
		},
		{
			name: "unknown purpose",
			change: func(v *AccountToken) {
				v.Purpose = "other"
			},
			want: ErrInvalidAccountToken,
		},
		{
			name: "zero creation",
			change: func(v *AccountToken) {
				v.CreatedAt = time.Time{}
			},
			want: ErrInvalidAccountToken,
		},
		{
			name: "excessive lifetime",
			change: func(v *AccountToken) {
				v.ExpiresAt = now.Add(time.Hour + time.Second)
			},
			want: ErrInvalidAccountToken,
		},
		{
			name: "empty lifetime",
			change: func(v *AccountToken) {
				v.ExpiresAt = now
			},
			want: ErrInvalidAccountToken,
		},
		{
			name: "use before creation",
			change: func(v *AccountToken) {
				before := now.Add(-time.Second)
				v.UsedAt = &before
			},
			want: ErrInvalidAccountToken,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := valid
			tc.change(&value)
			if err := value.Validate(); !errors.Is(err, tc.want) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		at     time.Time
		used   bool
		active bool
	}{
		{
			name:   "before creation",
			at:     now.Add(-time.Nanosecond),
			used:   false,
			active: false,
		},
		{
			name:   "at creation",
			at:     now,
			used:   false,
			active: true,
		},
		{
			name:   "before expiration",
			at:     valid.ExpiresAt.Add(-time.Nanosecond),
			used:   false,
			active: true,
		},
		{
			name:   "at expiration",
			at:     valid.ExpiresAt,
			used:   false,
			active: false,
		},
		{
			name:   "used",
			at:     now,
			used:   true,
			active: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := valid
			if tc.used {
				value.UsedAt = &now
			}
			if value.Active(tc.at) != tc.active {
				t.Fatal("incorrect token state")
			}
		})
	}
}
