package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/horizoonn/relay/platform/pkg/ratelimit"

	"github.com/horizoonn/relay/identity/internal/domain"
	identitylimit "github.com/horizoonn/relay/identity/internal/ratelimit"
)

type loginLimiter struct {
	err     error
	calls   int
	subject string
}

func (l *loginLimiter) Allow(
	_ context.Context,
	scope identitylimit.Scope,
	subject string,
) error {
	if scope != identitylimit.LoginAccount {
		panic("unexpected scope")
	}
	l.calls++
	l.subject = subject
	return l.err
}

type loginUsers struct {
	UserRepository
	called bool
}

func (u *loginUsers) GetByEmailWithPasswordHash(context.Context, string) (domain.User, string, error) {
	u.called = true
	return domain.User{}, "", errors.New("unexpected database access")
}

func TestLoginAdmission(t *testing.T) {
	for _, tc := range []struct {
		name     string
		email    string
		limitErr error
		expected error
		calls    int
	}{
		{
			name:  "account rate exceeded",
			email: "  Case@EXAMPLE.COM  ",
			limitErr: &ratelimit.ExceededError{
				RetryAfter: time.Second,
			},
			expected: nil,
			calls:    1,
		},
		{
			name:     "Redis unavailable",
			email:    "Case@EXAMPLE.COM",
			limitErr: ratelimit.ErrUnavailable,
			expected: ratelimit.ErrUnavailable,
			calls:    1,
		},
		{
			name:     "invalid input",
			email:    "invalid",
			limitErr: nil,
			expected: ErrInvalidCredentials,
			calls:    0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limiter := &loginLimiter{
				err: tc.limitErr,
			}
			users := &loginUsers{}
			s := &Service{
				users:   users,
				limiter: limiter,
			}
			_, err := s.Login(t.Context(), tc.email, "some input")
			if tc.limitErr != nil && tc.expected == nil {
				var exceeded *ratelimit.ExceededError
				if !errors.As(err, &exceeded) {
					t.Fatal(err)
				}
			} else if !errors.Is(err, tc.expected) {
				t.Fatal(err)
			}
			if users.called || limiter.calls != tc.calls {
				t.Fatalf("database=%v limiter calls=%d", users.called, limiter.calls)
			}
			if tc.calls > 0 && limiter.subject != "Case@example.com" {
				t.Fatalf("subject=%q", limiter.subject)
			}
		})
	}
}
