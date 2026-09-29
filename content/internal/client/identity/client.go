package identity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"
	"uuid"

	identityv1 "github.com/horizoonn/relay/shared/pkg/proto/relay/identity/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"github.com/horizoonn/relay/content/internal/auth"
)

type Client struct {
	conn    *grpc.ClientConn
	service identityv1.IdentityServiceClient
	health  grpc_health_v1.HealthClient
	timeout time.Duration
}

type Options struct {
	Address      string
	ServiceToken string
	CAFile       string
	ServerName   string
	Timeout      time.Duration
}

type serviceToken string

func (t serviceToken) GetRequestMetadata(
	context.Context,
	...string,
) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + string(t)}, nil
}

func (serviceToken) RequireTransportSecurity() bool { return true }

func New(cfg Options) (*Client, error) {
	if cfg.Address == "" || cfg.ServiceToken == "" || cfg.Timeout <= 0 {
		return nil, errors.New("identity address, service token and timeout are required")
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system CAs: %w", err)
	}
	if cfg.CAFile != "" {
		certPEM, readErr := os.ReadFile(cfg.CAFile)
		if readErr != nil {
			return nil, fmt.Errorf("read identity CA file: %w", readErr)
		}
		if !roots.AppendCertsFromPEM(certPEM) {
			return nil, errors.New("identity CA file contains no certificates")
		}
	}
	conn, err := grpc.NewClient(cfg.Address,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
			ServerName: cfg.ServerName,
		})),
		grpc.WithPerRPCCredentials(serviceToken(cfg.ServiceToken)),
	)
	if err != nil {
		return nil, fmt.Errorf("create Identity connection: %w", err)
	}
	return &Client{
		conn:    conn,
		service: identityv1.NewIdentityServiceClient(conn),
		health:  grpc_health_v1.NewHealthClient(conn),
		timeout: cfg.Timeout,
	}, nil
}

func (c *Client) Close() error { return c.conn.Close() }

func (c *Client) Introspect(
	ctx context.Context,
	accessToken string,
) (uuid.UUID, error) {
	if accessToken == "" {
		return uuid.Nil(), auth.ErrUnauthenticated
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	response, err := c.service.Introspect(ctx, &identityv1.IntrospectRequest{
		AccessToken: accessToken,
	})
	if err != nil {
		return uuid.Nil(), mapError(err)
	}
	if !response.GetValid() {
		return uuid.Nil(), auth.ErrUnauthenticated
	}
	userID, userErr := uuid.Parse(response.GetUserId())
	sessionID, sessionErr := uuid.Parse(response.GetSessionId())
	if userErr != nil || sessionErr != nil || userID == uuid.Nil() || sessionID == uuid.Nil() {
		return uuid.Nil(), fmt.Errorf("%w: malformed Identity response", auth.ErrIdentityUnavailable)
	}
	return userID, nil
}

func (c *Client) ValidateCSRF(
	ctx context.Context,
	accessToken,
	csrfToken string,
) error {
	if accessToken == "" {
		return auth.ErrUnauthenticated
	}
	if csrfToken == "" {
		return auth.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	response, err := c.service.ValidateCSRF(ctx, &identityv1.ValidateCSRFRequest{
		AccessToken: accessToken,
		CsrfToken:   csrfToken,
	})
	if err != nil {
		return mapError(err)
	}
	if !response.GetAccessValid() {
		return auth.ErrUnauthenticated
	}
	if !response.GetCsrfValid() {
		return auth.ErrForbidden
	}
	return nil
}

func (c *Client) Check(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	response, err := c.health.Check(ctx, &grpc_health_v1.HealthCheckRequest{
		Service: identityv1.IdentityService_ServiceDesc.ServiceName,
	})
	if err != nil {
		return mapError(err)
	}
	if response.GetStatus() != grpc_health_v1.HealthCheckResponse_SERVING {
		return auth.ErrIdentityUnavailable
	}
	return nil
}

func mapError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: gRPC status %s", auth.ErrIdentityUnavailable, status.Code(err))
}
