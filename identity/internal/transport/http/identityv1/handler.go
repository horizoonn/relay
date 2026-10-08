package identityv1

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"uuid"

	"github.com/horizoonn/relay/platform/pkg/httpmiddleware"
	"github.com/horizoonn/relay/platform/pkg/security/accessjwt"
	identityapi "github.com/horizoonn/relay/shared/pkg/openapi/identity/v1"
	"github.com/ogen-go/ogen/middleware"
	"go.uber.org/zap"

	identitylimit "github.com/horizoonn/relay/identity/internal/ratelimit"
	"github.com/horizoonn/relay/identity/internal/usecase/auth"
	"github.com/horizoonn/relay/identity/internal/usecase/session"
)

type AuthService interface {
	Register(context.Context, string, string) (uuid.UUID, error)
	Login(context.Context, string, string) (auth.LoginResult, error)
}

type RateLimiter interface {
	Allow(context.Context, identitylimit.Scope, string) error
}

type AccountRequests interface {
	RequestVerification(context.Context, string) error
	RequestPasswordReset(context.Context, string) error
}
type AccountService interface {
	VerifyEmail(context.Context, string) error
	ResetPassword(context.Context, string, string) error
}

type Handler struct {
	requests AccountRequests
	account  AccountService
	limiter  RateLimiter
	auth     AuthService
	sessions SessionService
	verifier AccessVerifier
	cursors  *CursorCodec
	log      *zap.Logger
}

type SessionService interface {
	GetCurrent(context.Context, uuid.UUID, uuid.UUID) (session.Current, error)
	Refresh(context.Context, string, string) (session.RefreshResult, error)
	Logout(context.Context, string, string) error
	ListActive(context.Context, uuid.UUID, uuid.UUID, session.ListParams) (session.Page, error)
	Revoke(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string) error
	RevokeAll(context.Context, uuid.UUID, uuid.UUID, string) error
}

type AccessVerifier interface {
	Verify(string) (accessjwt.Access, error)
}

func NewHandler(
	service AuthService,
	sessions SessionService,
	verifier AccessVerifier,
	cursors *CursorCodec,
	log *zap.Logger,
	limiter RateLimiter,
	requests AccountRequests,
	account AccountService,
) (*Handler, error) {
	handler := &Handler{
		auth:     service,
		requests: requests,
		account:  account,
		limiter:  limiter,
		sessions: sessions,
		verifier: verifier,
		cursors:  cursors,
		log:      log,
	}
	if err := handler.validate(); err != nil {
		return nil, err
	}
	return handler, nil
}

func (h *Handler) validate() error {
	if h == nil || h.auth == nil || h.sessions == nil || h.verifier == nil ||
		h.cursors == nil || len(h.cursors.key) < 32 || h.log == nil ||
		h.limiter == nil || h.requests == nil || h.account == nil {
		return errors.New(
			"identity HTTP handler requires auth, session service, verifier, cursor codec, " +
				"logger, rate limiter and account services",
		)
	}
	return nil
}

var (
	_ identityapi.Handler         = (*Handler)(nil)
	_ identityapi.SecurityHandler = (*Handler)(nil)
)

func NewServer(
	handler *Handler,
	allowedOrigin string,
	trustedProxies []netip.Prefix,
) (http.Handler, error) {
	if err := handler.validate(); err != nil {
		return nil, err
	}
	origin, err := url.Parse(allowedOrigin)
	if err != nil || origin == nil || origin.Scheme != "https" || origin.Hostname() == "" ||
		origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.ForceQuery ||
		origin.Fragment != "" || origin.Opaque != "" || origin.String() != allowedOrigin {
		return nil, errors.New("invalid allowed identity HTTPS origin")
	}
	server, err := identityapi.NewServer(handler, handler,
		identityapi.WithMiddleware(func(req middleware.Request, next middleware.Next) (middleware.Response, error) {
			httpmiddleware.SetOperation(req.Context, req.OperationName)
			return next(req)
		}),
		identityapi.WithErrorHandler(handler.decodeError),
		identityapi.WithNotFound(handler.notFound),
		identityapi.WithMethodNotAllowed(handler.methodNotAllowed),
	)
	if err != nil {
		return nil, fmt.Errorf("create Identity API server: %w", err)
	}
	protected := handler.browserRequests(handler.limitRequests(server, trustedProxies), allowedOrigin)
	recovered := httpmiddleware.Recovery(handler.log, protected, func(w http.ResponseWriter, r *http.Request) {
		handler.writeProblem(w, problemFor(r.Context(), http.StatusInternalServerError,
			identityapi.ProblemCodeINTERNALERROR, "Internal server error", "An unexpected error occurred"))
	})
	return requestMiddleware(recovered), nil
}
