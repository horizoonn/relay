package identity

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	identityv1 "github.com/horizoonn/relay/shared/pkg/proto/relay/identity/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/horizoonn/relay/content/internal/auth"
)

const (
	testUserID    = "18d1fdc1-c413-4784-9640-17d15828791c"
	testSessionID = "292328de-ae52-46bf-ae85-e15410a8305b"
)

type identityServer struct {
	identityv1.UnimplementedIdentityServiceServer
}

func (identityServer) Introspect(
	ctx context.Context,
	request *identityv1.IntrospectRequest,
) (*identityv1.IntrospectResponse, error) {
	if err := checkServiceToken(ctx); err != nil {
		return nil, err
	}
	if request.GetAccessToken() != "valid-access" {
		if request.GetAccessToken() == "malformed" {
			return &identityv1.IntrospectResponse{
				Valid: true,
			}, nil
		}
		return &identityv1.IntrospectResponse{}, nil
	}
	return &identityv1.IntrospectResponse{
		Valid:     true,
		UserId:    testUserID,
		SessionId: testSessionID,
	}, nil
}

func (identityServer) ValidateCSRF(
	ctx context.Context,
	request *identityv1.ValidateCSRFRequest,
) (*identityv1.ValidateCSRFResponse, error) {
	if err := checkServiceToken(ctx); err != nil {
		return nil, err
	}
	if request.GetAccessToken() != "valid-access" {
		return &identityv1.ValidateCSRFResponse{}, nil
	}
	if request.GetCsrfToken() != "valid-csrf" {
		return &identityv1.ValidateCSRFResponse{
			AccessValid: true,
		}, nil
	}
	return &identityv1.ValidateCSRFResponse{
		AccessValid: true,
		CsrfValid:   true,
	}, nil
}

func checkServiceToken(ctx context.Context) error {
	values, _ := metadata.FromIncomingContext(ctx)
	if got := values.Get("authorization"); len(got) != 1 || got[0] != "Bearer service-token" {
		return status.Error(codes.PermissionDenied, "invalid service identity")
	}
	return nil
}

func TestClientOverTLS(t *testing.T) {
	server := grpc.NewServer()
	identityv1.RegisterIdentityServiceServer(server, identityServer{})
	probe := health.NewServer()
	probe.SetServingStatus(identityv1.IdentityService_ServiceDesc.ServiceName, grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(server, probe)
	tlsServer := httptest.NewUnstartedServer(server)
	tlsServer.EnableHTTP2 = true
	tlsServer.StartTLS()
	t.Cleanup(tlsServer.Close)
	certFile := t.TempDir() + "/identity-ca.pem"
	cert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: tlsServer.Certificate().Raw,
	})
	if err := os.WriteFile(certFile, cert, 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := New(Options{
		Address:      strings.TrimPrefix(tlsServer.URL, "https://"),
		ServiceToken: "service-token",
		CAFile:       certFile,
		Timeout:      time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	if checkErr := client.Check(ctx); checkErr != nil {
		t.Fatalf("Identity readiness: %v", checkErr)
	}
	userID, err := client.Introspect(ctx, "valid-access")
	if err != nil || userID.String() != testUserID {
		t.Fatalf("Introspect: user=%s error=%v", userID, err)
	}
	if _, callErr := client.Introspect(ctx, "invalid"); !errors.Is(callErr, auth.ErrUnauthenticated) {
		t.Fatalf("invalid access: %v", callErr)
	}
	if _, callErr := client.Introspect(ctx, "malformed"); !errors.Is(callErr, auth.ErrIdentityUnavailable) {
		t.Fatalf("malformed Identity response: %v", callErr)
	}
	if callErr := client.ValidateCSRF(ctx, "revoked-access", "valid-csrf"); !errors.Is(callErr, auth.ErrUnauthenticated) {
		t.Fatalf("revoked access during CSRF check: %v", callErr)
	}
	if callErr := client.ValidateCSRF(ctx, "valid-access", "wrong"); !errors.Is(callErr, auth.ErrForbidden) {
		t.Fatalf("invalid CSRF: %v", callErr)
	}
	if callErr := client.ValidateCSRF(ctx, "valid-access", "valid-csrf"); callErr != nil {
		t.Fatalf("valid CSRF: %v", callErr)
	}
	wrongService, err := New(Options{
		Address:      strings.TrimPrefix(tlsServer.URL, "https://"),
		ServiceToken: "wrong-service-token",
		CAFile:       certFile,
		Timeout:      time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wrongService.Close() })
	if _, err := wrongService.Introspect(ctx, "valid-access"); !errors.Is(err, auth.ErrIdentityUnavailable) {
		t.Fatalf("invalid service identity: %v", err)
	}
	tlsServer.Close()
	if _, err := client.Introspect(ctx, "valid-access"); !errors.Is(err, auth.ErrIdentityUnavailable) {
		t.Fatalf("unavailable Identity: %v", err)
	}
}
