package session_test

import (
	"errors"
	"testing"
	"testing/synctest"
	"time"
	"uuid"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/horizoonn/relay/identity/internal/domain"
	"github.com/horizoonn/relay/identity/internal/secret"
	"github.com/horizoonn/relay/identity/internal/usecase/session"
	"github.com/horizoonn/relay/identity/internal/usecase/session/mocks"
)

type managementSessions struct {
	sessionLookup
	target    domain.Session
	targetErr error
	writeErr  error
}

func activeSessionForTest(t *testing.T) (domain.User, domain.Session, string) {
	t.Helper()
	now := time.Now().UTC().Add(-time.Minute)
	user, err := domain.NewUser("user@example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := secret.Generate()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := secret.Digest(csrf)
	if err != nil {
		t.Fatal(err)
	}
	caller, err := domain.NewSession(user.ID, hash, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return user, caller, csrf
}

func TestRevokeSession(t *testing.T) {
	t.Parallel()
	user, caller, csrf := activeSessionForTest(t)
	now := caller.CreatedAt
	target := caller
	target.ID = uuid.NewV7()
	storageErr := errors.New("storage unavailable")
	tests := []struct {
		name                             string
		change                           func(*userLookup, *managementSessions, *uuid.UUID, *string)
		wantErr                          error
		revoke                           bool
		readUser, readCaller, readTarget bool
	}{
		{
			name:       "other own session",
			readUser:   true,
			readCaller: true,
			readTarget: true,
			change: func(*userLookup, *managementSessions, *uuid.UUID, *string) {
			},
			wantErr: nil,
			revoke:  true,
		},
		{
			name:       "current session",
			readUser:   true,
			readCaller: true,
			change: func(_ *userLookup, _ *managementSessions, id *uuid.UUID, _ *string) {
				*id = caller.ID
			},
			wantErr: nil,
			revoke:  true,
		},
		{
			name:       "already revoked target",
			readUser:   true,
			readCaller: true,
			readTarget: true,
			change: func(_ *userLookup, s *managementSessions, _ *uuid.UUID, _ *string) {
				s.target.RevokedAt = &now
			},
			wantErr: nil,
			revoke:  false,
		},
		{
			name:       "expired target",
			readUser:   true,
			readCaller: true,
			readTarget: true,
			change: func(_ *userLookup, s *managementSessions, _ *uuid.UUID, _ *string) {
				s.target.ExpiresAt = now.Add(time.Second)
			},
			wantErr: nil,
			revoke:  false,
		},
		{
			name:       "missing target",
			readUser:   true,
			readCaller: true,
			readTarget: true,
			change: func(_ *userLookup, s *managementSessions, _ *uuid.UUID, _ *string) {
				s.targetErr = domain.ErrNotFound
			},
			wantErr: session.ErrSessionNotFound,
			revoke:  false,
		},
		{
			name:       "foreign target",
			readUser:   true,
			readCaller: true,
			readTarget: true,
			change: func(_ *userLookup, s *managementSessions, _ *uuid.UUID, _ *string) {
				s.target.UserID = uuid.NewV7()
			},
			wantErr: session.ErrSessionNotFound,
			revoke:  false,
		},
		{
			name: "empty target ID",
			change: func(_ *userLookup, _ *managementSessions, id *uuid.UUID, _ *string) {
				*id = uuid.Nil()
			},
			wantErr: session.ErrInvalidQuery,
			revoke:  false,
		},
		{
			name:       "revoked caller",
			readUser:   true,
			readCaller: true,
			change: func(_ *userLookup, s *managementSessions, _ *uuid.UUID, _ *string) {
				s.session.RevokedAt = &now
			},
			wantErr: session.ErrUnauthenticated,
			revoke:  false,
		},
		{
			name:       "expired caller",
			readUser:   true,
			readCaller: true,
			change: func(_ *userLookup, s *managementSessions, _ *uuid.UUID, _ *string) {
				s.session.ExpiresAt = now.Add(time.Second)
			},
			wantErr: session.ErrUnauthenticated,
			revoke:  false,
		},
		{
			name:     "disabled account",
			readUser: true,
			change: func(u *userLookup, _ *managementSessions, _ *uuid.UUID, _ *string) {
				u.user.State = domain.UserDisabled
			},
			wantErr: session.ErrUnauthenticated,
			revoke:  false,
		},
		{
			name:       "unknown caller",
			readUser:   true,
			readCaller: true,
			change: func(_ *userLookup, s *managementSessions, _ *uuid.UUID, _ *string) {
				s.err = domain.ErrNotFound
			},
			wantErr: session.ErrUnauthenticated,
			revoke:  false,
		},
		{
			name:       "wrong CSRF",
			readUser:   true,
			readCaller: true,
			change: func(_ *userLookup, _ *managementSessions, _ *uuid.UUID, raw *string) {
				*raw, _ = secret.Generate()
			},
			wantErr: session.ErrCSRF,
			revoke:  false,
		},
		{
			name: "malformed CSRF",
			change: func(_ *userLookup, _ *managementSessions, _ *uuid.UUID, raw *string) {
				*raw = "invalid"
			},
			wantErr: session.ErrCSRF,
			revoke:  false,
		},
		{
			name:     "account storage failure",
			readUser: true,
			change: func(u *userLookup, _ *managementSessions, _ *uuid.UUID, _ *string) {
				u.err = storageErr
			},
			wantErr: storageErr,
			revoke:  false,
		},
		{
			name:       "target storage failure",
			readUser:   true,
			readCaller: true,
			readTarget: true,
			change: func(_ *userLookup, s *managementSessions, _ *uuid.UUID, _ *string) {
				s.targetErr = storageErr
			},
			wantErr: storageErr,
			revoke:  false,
		},
		{
			name:    "revocation storage failure",
			change:  func(_ *userLookup, s *managementSessions, _ *uuid.UUID, _ *string) { s.writeErr = storageErr },
			wantErr: storageErr, revoke: true, readUser: true, readCaller: true, readTarget: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			users := userLookup{
				user: user,
			}
			sessions := managementSessions{
				sessionLookup: sessionLookup{
					session: caller,
				},
				target: target,
			}
			targetID, rawCSRF := target.ID, csrf
			tt.change(&users, &sessions, &targetID, &rawCSRF)
			ctx := t.Context()
			repository := mocks.NewMockSessionRepository(t)
			userRepository := mocks.NewMockUserRepository(t)
			if tt.readUser {
				userRepository.EXPECT().GetForUpdate(ctx, user.ID).Return(users.user, users.err).Once()
			}
			if tt.readCaller {
				repository.EXPECT().GetForUpdate(ctx, user.ID, caller.ID).Return(sessions.session, sessions.err).Once()
			}
			if tt.readTarget {
				repository.EXPECT().GetForUpdate(ctx, user.ID, targetID).Return(sessions.target, sessions.targetErr).Once()
			}
			if tt.revoke {
				before := time.Now().UTC()
				repository.EXPECT().Revoke(ctx, user.ID, targetID, mock.MatchedBy(func(at time.Time) bool {
					return !at.Before(before) && !at.After(time.Now().UTC())
				})).Return(sessions.writeErr).Once()
			}
			service, newErr := session.NewService(userRepository, repository, directTransaction{}, unusedIssuer{})
			if newErr != nil {
				t.Fatal(newErr)
			}
			err := service.Revoke(ctx, user.ID, caller.ID, targetID, rawCSRF)
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestListParamsValidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		params session.ListParams
		valid  bool
	}{
		{
			name: "minimum",
			params: session.ListParams{
				Limit: 1,
			},
			valid: true,
		},
		{
			name: "maximum",
			params: session.ListParams{
				Limit: 100,
			},
			valid: true,
		},
		{
			name:   "zero",
			params: session.ListParams{},
			valid:  false,
		},
		{
			name: "above maximum",
			params: session.ListParams{
				Limit: 101,
			},
			valid: false,
		},
		{
			name: "negative",
			params: session.ListParams{
				Limit: -1,
			},
			valid: false,
		},
		{
			name: "empty anchor",
			params: session.ListParams{
				Limit: 20,
				After: &session.Anchor{},
			},
			valid: false,
		},
		{
			name: "missing anchor ID",
			params: session.ListParams{
				Limit: 20,
				After: &session.Anchor{
					CreatedAt: time.Now(),
				},
			},
			valid: false,
		},
		{
			name: "missing anchor time",
			params: session.ListParams{
				Limit: 20,
				After: &session.Anchor{
					ID: uuid.NewV7(),
				},
			},
			valid: false,
		},
		{
			name: "valid anchor",
			params: session.ListParams{
				Limit: 20,
				After: &session.Anchor{
					CreatedAt: time.Now(),
					ID:        uuid.NewV7(),
				},
			},
			valid: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.params.Validate(); (err == nil) != tt.valid {
				t.Fatalf("Validate() = %v; want valid=%v", err, tt.valid)
			}
		})
	}
}

func TestRevokeAll(t *testing.T) {
	storageErr := errors.New("session revocation failed")
	for _, tt := range []struct {
		name                string
		callerRevoked       bool
		persistErr, wantErr error
	}{
		{name: "success"},
		{name: "storage failure", persistErr: storageErr, wantErr: storageErr},
		{name: "revoked caller", callerRevoked: true, wantErr: session.ErrUnauthenticated},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				user, caller, csrf := activeSessionForTest(t)
				now := time.Now().UTC()
				if tt.callerRevoked {
					caller.RevokedAt = &now
				}
				users, sessions := mocks.NewMockUserRepository(t), mocks.NewMockSessionRepository(t)
				ctx := t.Context()
				users.EXPECT().GetForUpdate(ctx, user.ID).Return(user, nil).Once()
				sessions.EXPECT().GetForUpdate(ctx, user.ID, caller.ID).Return(caller, nil).Once()
				if !tt.callerRevoked {
					sessions.EXPECT().RevokeAll(ctx, user.ID, now).Return(tt.persistErr).Once()
				}
				service, err := session.NewService(users, sessions, directTransaction{}, unusedIssuer{})
				require.NoError(t, err)
				require.ErrorIs(t, service.RevokeAll(ctx, user.ID, caller.ID, csrf), tt.wantErr)
			})
		})
	}
}

func TestListActive(t *testing.T) {
	storageErr := errors.New("session listing failed")
	for _, tt := range []struct {
		name       string
		storageErr error
	}{
		{name: "success"}, {name: "storage failure", storageErr: storageErr},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				user, caller, _ := activeSessionForTest(t)
				users, sessions := mocks.NewMockUserRepository(t), mocks.NewMockSessionRepository(t)
				ctx := t.Context()
				params := session.ListParams{Limit: 2, After: &session.Anchor{ID: uuid.NewV7(), CreatedAt: caller.CreatedAt}}
				page := session.Page{
					Sessions: []session.Info{{
						ID: caller.ID, CreatedAt: caller.CreatedAt,
						AuthenticatedAt: caller.AuthenticatedAt, LastSeenAt: caller.LastSeenAt, ExpiresAt: caller.ExpiresAt,
					}},
					Next: &session.Anchor{ID: caller.ID, CreatedAt: caller.CreatedAt},
				}
				sessions.EXPECT().Get(ctx, user.ID, caller.ID).Return(caller, nil).Once()
				users.EXPECT().Get(ctx, user.ID).Return(user, nil).Once()
				sessions.EXPECT().ListActive(ctx, user.ID, time.Now().UTC(), params).Return(page, tt.storageErr).Once()
				service, err := session.NewService(users, sessions, directTransaction{}, unusedIssuer{})
				require.NoError(t, err)
				got, err := service.ListActive(ctx, user.ID, caller.ID, params)
				require.ErrorIs(t, err, tt.storageErr)
				if tt.storageErr != nil {
					require.Equal(t, session.Page{}, got)
				} else {
					require.Equal(t, page, got)
				}
			})
		})
	}
}
