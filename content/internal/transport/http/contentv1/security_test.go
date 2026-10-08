package contentv1

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"uuid"

	"github.com/horizoonn/relay/platform/pkg/security/accessjwt"
	contentapi "github.com/horizoonn/relay/shared/pkg/openapi/content/v1"
)

type fakeVerifier struct {
	owner uuid.UUID
	token string
	csrf  string
	err   error
}

func (f fakeVerifier) Verify(token string) (accessjwt.Access, error) {
	if f.err != nil {
		return accessjwt.Access{}, f.err
	}
	if f.token != "" && token != f.token {
		return accessjwt.Access{}, errUnauthenticated
	}
	return accessjwt.Access{
		UserID:    f.owner,
		SessionID: uuid.NewV7(),
		CSRFHash:  sha256.Sum256([]byte(f.csrf)),
	}, nil
}

const testCSRF = "ccccccccccccccccccccccccccccccccccccccccccc"

func TestSecurityCSRFOrigin(t *testing.T) {
	t.Parallel()
	owner := uuid.New()
	s := NewSecurity(fakeVerifier{
		owner: owner,
		token: "access",
		csrf:  testCSRF,
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
			csrf:   testCSRF,
		},
		{
			name:    "invalid origin",
			origin:  "https://evil.example",
			csrf:    testCSRF,
			wantErr: errForbidden,
		},
		{
			name:    "invalid token",
			origin:  testOrigin,
			csrf:    "wrong",
			wantErr: errForbidden,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := s.HandleCsrfHeader(withBrowserRequest(ctx, browserRequest{
				origin:          tt.origin,
				csrfCookie:      testCSRF,
				originCount:     1,
				csrfHeaderCount: 1,
			}), contentapi.CaptureItemOperation,
				contentapi.CsrfHeader{
					APIKey: tt.csrf,
				})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("CSRF error = %v; want %v", err, tt.wantErr)
			}
		})
	}
}
