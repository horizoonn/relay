package session_test

import (
	"context"
	"errors"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/platform/pkg/security/accessjwt"

	"github.com/horizoonn/relay/identity/internal/domain"
	"github.com/horizoonn/relay/identity/internal/usecase/session"
	"github.com/horizoonn/relay/identity/internal/usecase/session/mocks"
)

type userLookup struct {
	user domain.User
	err  error
}

type sessionLookup struct {
	session domain.Session
	err     error
}

type directTransaction struct{}

func (directTransaction) WithinTransaction(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

type unusedIssuer struct{}

func (unusedIssuer) Issue(uuid.UUID, uuid.UUID, [32]byte, time.Time) (accessjwt.Token, error) {
	return accessjwt.Token{}, errors.New("unexpected signing")
}

func TestGetCurrent(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Add(-time.Minute)
	user, err := domain.NewUser("user@example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	current, err := domain.NewSession(user.ID, [32]byte{1}, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	storageErr := errors.New("database unavailable")
	for _, tc := range []struct {
		name     string
		change   func(*userLookup, *sessionLookup)
		want     error
		readUser bool
	}{
		{
			name:     "active",
			readUser: true,
			change: func(*userLookup, *sessionLookup) {
			},
			want: nil,
		},
		{
			name: "revoked",
			change: func(_ *userLookup, s *sessionLookup) {
				s.session.RevokedAt = &now
			},
			want: session.ErrUnauthenticated,
		},
		{
			name: "expired",
			change: func(_ *userLookup, s *sessionLookup) {
				s.session.ExpiresAt = now.Add(time.Second)
			},
			want: session.ErrUnauthenticated,
		},
		{
			name: "future",
			change: func(_ *userLookup, s *sessionLookup) {
				future := time.Now().Add(time.Hour)
				s.session.CreatedAt = future
				s.session.AuthenticatedAt = future
				s.session.LastSeenAt = future
				s.session.ExpiresAt = future.Add(time.Hour)
			},
			want: session.ErrUnauthenticated,
		},
		{
			name:     "disabled",
			readUser: true,
			change: func(u *userLookup, _ *sessionLookup) {
				u.user.State = domain.UserDisabled
			},
			want: session.ErrUnauthenticated,
		},
		{
			name:     "missing user",
			readUser: true,
			change: func(u *userLookup, _ *sessionLookup) {
				u.err = domain.ErrNotFound
			},
			want: session.ErrUnauthenticated,
		},
		{
			name: "missing session",
			change: func(_ *userLookup, s *sessionLookup) {
				s.err = domain.ErrNotFound
			},
			want: session.ErrUnauthenticated,
		},
		{
			name: "foreign session",
			change: func(_ *userLookup, s *sessionLookup) {
				s.session.UserID = uuid.NewV7()
			},
			want: session.ErrUnauthenticated,
		},
		{
			name: "wrong session",
			change: func(_ *userLookup, s *sessionLookup) {
				s.session.ID = uuid.NewV7()
			},
			want: session.ErrUnauthenticated,
		},
		{
			name:     "user storage failure",
			readUser: true,
			change: func(u *userLookup, _ *sessionLookup) {
				u.err = storageErr
			},
			want: storageErr,
		},
		{
			name: "session storage failure",
			change: func(_ *userLookup, s *sessionLookup) {
				s.err = storageErr
			},
			want: storageErr,
		},
		{
			name:     "invalid stored user",
			readUser: true,
			change: func(u *userLookup, _ *sessionLookup) {
				u.user.Email = "invalid"
			},
			want: domain.ErrInvalidUser,
		},
		{
			name: "invalid stored session",
			change: func(_ *userLookup, s *sessionLookup) {
				s.session.CSRFHash = [32]byte{}
			},
			want: domain.ErrInvalidSession,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			users, sessions := userLookup{
				user: user,
			}, sessionLookup{
				session: current,
			}
			tc.change(&users, &sessions)
			ctx := t.Context()
			userRepository := mocks.NewMockUserRepository(t)
			sessionRepository := mocks.NewMockSessionRepository(t)
			sessionRepository.EXPECT().Get(ctx, user.ID, current.ID).Return(sessions.session, sessions.err).Once()
			if tc.readUser {
				userRepository.EXPECT().Get(ctx, user.ID).Return(users.user, users.err).Once()
			}
			service, newErr := session.NewService(userRepository, sessionRepository, directTransaction{}, unusedIssuer{})
			if newErr != nil {
				t.Fatal(newErr)
			}
			result, getErr := service.GetCurrent(t.Context(), user.ID, current.ID)
			if !errors.Is(getErr, tc.want) {
				t.Fatalf("unexpected error: %v", getErr)
			}
			if tc.want == nil {
				if result.User.ID != user.ID || result.Session.ID != current.ID {
					t.Fatal("incorrect current session")
				}
			} else if result != (session.Current{}) {
				t.Fatal("failure returned user or session data")
			}
		})
	}
}

func TestGetCurrentRejectsEmptyIDs(t *testing.T) {
	service, err := session.NewService(mocks.NewMockUserRepository(t), mocks.NewMockSessionRepository(t), directTransaction{}, unusedIssuer{})
	if err != nil {
		t.Fatal(err)
	}
	for _, ids := range [][2]uuid.UUID{{uuid.Nil(), uuid.NewV7()}, {uuid.NewV7(), uuid.Nil()}} {
		if _, err := service.GetCurrent(t.Context(), ids[0], ids[1]); !errors.Is(err, session.ErrUnauthenticated) {
			t.Fatal(err)
		}
	}
}
