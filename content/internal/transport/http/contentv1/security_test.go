package contentv1

import (
	"context"
	"errors"
	"testing"
	"uuid"

	contentapi "github.com/horizoonn/relay/shared/pkg/openapi/content/v1"

	"github.com/horizoonn/relay/content/internal/auth"
)

type fakeAuthenticator struct {
	owner uuid.UUID
	token string
	csrf  string
	err   error
}

func (f fakeAuthenticator) Introspect(
	_ context.Context,
	token string,
) (uuid.UUID, error) {
	if f.err != nil {
		return uuid.Nil(), f.err
	}
	if f.token != "" && token != f.token {
		return uuid.Nil(), auth.ErrUnauthenticated
	}
	return f.owner, nil
}

func (f fakeAuthenticator) ValidateCSRF(
	_ context.Context,
	token,
	csrf string,
) error {
	if token != f.token || csrf != f.csrf {
		return auth.ErrForbidden
	}
	return nil
}

func TestSecurityCSRFOrigin(t *testing.T) {
	t.Parallel()
	owner := uuid.New()
	s := NewSecurity(fakeAuthenticator{
		owner: owner,
		token: "access",
		csrf:  "csrf",
	}, "https://relay.example")
	ctx, err := s.HandleAccessCookie(
		context.Background(),
		contentapi.CaptureItemOperation,
		contentapi.AccessCookie{
			APIKey: "access",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	got, err := PrincipalFromContext(ctx)
	if err != nil || got != owner {
		t.Fatalf("principal = %s, %v; want %s", got, err, owner)
	}
	for _, tt := range []struct {
		name    string
		origin  string
		csrf    string
		wantErr error
	}{
		{
			name:   "valid",
			origin: testOrigin,
			csrf:   "csrf",
		},
		{
			name:    "invalid origin",
			origin:  "https://evil.example",
			csrf:    "csrf",
			wantErr: auth.ErrForbidden,
		},
		{
			name:    "invalid token",
			origin:  testOrigin,
			csrf:    "wrong",
			wantErr: auth.ErrForbidden,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := s.HandleCsrfHeader(withRequestOrigin(ctx, tt.origin), contentapi.CaptureItemOperation,
				contentapi.CsrfHeader{
					APIKey: tt.csrf,
				})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("CSRF error = %v; want %v", err, tt.wantErr)
			}
		})
	}
}
