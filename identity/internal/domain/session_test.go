package domain

import (
	"testing"
	"time"
	"uuid"
)

func TestSessionActive(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, time.October, 1, 12, 0, 0, 0, time.UTC)
	current, err := NewSession(uuid.NewV7(), [32]byte{1}, createdAt, createdAt.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	revokedAt := createdAt.Add(time.Minute)
	tests := []struct {
		name      string
		now       time.Time
		revokedAt *time.Time
		want      bool
	}{
		{
			name: "before creation",
			now:  createdAt.Add(-time.Nanosecond),
		},
		{
			name: "at creation",
			now:  createdAt,
			want: true,
		},
		{
			name: "before expiry",
			now:  current.ExpiresAt.Add(-time.Nanosecond),
			want: true,
		},
		{
			name: "at expiry",
			now:  current.ExpiresAt,
		},
		{
			name: "after expiry",
			now:  current.ExpiresAt.Add(time.Nanosecond),
		},
		{
			name:      "revoked",
			now:       revokedAt,
			revokedAt: &revokedAt,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			session := current
			session.RevokedAt = tt.revokedAt
			if got := session.Active(tt.now); got != tt.want {
				t.Errorf("Active() = %v, want %v", got, tt.want)
			}
		})
	}
}
