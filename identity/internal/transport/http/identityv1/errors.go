package identityv1

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/horizoonn/relay/platform/pkg/httpmiddleware"
	"github.com/horizoonn/relay/platform/pkg/logger"
	"github.com/horizoonn/relay/platform/pkg/ratelimit"
	identityapi "github.com/horizoonn/relay/shared/pkg/openapi/identity/v1"
	"github.com/ogen-go/ogen/ogenerrors"
	"go.uber.org/zap"

	"github.com/horizoonn/relay/identity/internal/domain"
	"github.com/horizoonn/relay/identity/internal/password"
	"github.com/horizoonn/relay/identity/internal/usecase/account"
	"github.com/horizoonn/relay/identity/internal/usecase/auth"
	"github.com/horizoonn/relay/identity/internal/usecase/session"
)

func problemFor(
	ctx context.Context,
	status int,
	code identityapi.ProblemCode,
	title, detail string,
) *identityapi.ProblemStatusCodeWithHeaders {
	return &identityapi.ProblemStatusCodeWithHeaders{
		StatusCode: status,
		XRequestID: httpmiddleware.RequestID(ctx),
		Response: identityapi.Problem{
			Type: url.URL{
				Scheme: "urn",
				Opaque: "relay:problem:" + strings.ToLower(strings.ReplaceAll(string(code), "_", "-")),
			},
			Status:    status,
			Code:      code,
			Title:     title,
			Detail:    detail,
			RequestID: httpmiddleware.RequestID(ctx),
		},
	}
}

func (h *Handler) NewError(ctx context.Context, err error) *identityapi.ProblemStatusCodeWithHeaders {
	status, code, title, detail := describeError(err)
	if status >= http.StatusInternalServerError {

		fields := logger.ErrorFields(err)
		switch {
		case errors.Is(err, ratelimit.ErrUnavailable):
			fields = []zap.Field{zap.String("error_kind", "redis_unavailable")}
		case errors.Is(err, password.ErrBusy):
			fields = []zap.Field{zap.String("error_kind", "password_capacity")}
		}
		h.log.Error("identity HTTP request failed", append([]zap.Field{
			zap.String("request_id", httpmiddleware.RequestID(ctx)),
			zap.Int("status", status),
		}, fields...)...)
	}
	problem := problemFor(ctx, status, code, title, detail)
	var exceeded *ratelimit.ExceededError
	if errors.As(err, &exceeded) {
		problem.RetryAfter = identityapi.NewOptString(strconv.Itoa(max(1, int(math.Ceil(exceeded.RetryAfter.Seconds())))))
	}
	if errors.Is(err, password.ErrBusy) {
		problem.RetryAfter = identityapi.NewOptString("1")
	}
	return problem
}

func describeError(err error) (int, identityapi.ProblemCode, string, string) {
	var securityError *ogenerrors.SecurityError
	var exceeded *ratelimit.ExceededError
	switch {
	case errors.As(err, &exceeded):
		return http.StatusTooManyRequests,
			identityapi.ProblemCodeRATELIMITED,
			"Too many requests",
			"Request rate exceeded; retry later"
	case errors.Is(err, ratelimit.ErrUnavailable), errors.Is(err, password.ErrBusy):
		return http.StatusServiceUnavailable,
			identityapi.ProblemCodeSERVICEUNAVAILABLE,
			"Service unavailable",
			"Request cannot be processed right now"
	case errors.Is(err, session.ErrSessionNotFound):
		return http.StatusNotFound, identityapi.ProblemCodeSESSIONNOTFOUND,
			"Session not found", "Session not found"
	case errors.Is(err, session.ErrInvalidQuery):
		return http.StatusBadRequest, identityapi.ProblemCodeINVALIDREQUEST,
			"Invalid request", "Invalid session query"
	case errors.Is(err, session.ErrCSRF):
		return http.StatusForbidden, identityapi.ProblemCodeFORBIDDEN, "Forbidden", "CSRF token is invalid"
	case errors.Is(err, session.ErrRefreshConflict):
		return http.StatusConflict, identityapi.ProblemCodeREFRESHCONFLICT,
			"Refresh conflict", "Refresh credential was already used; retry with the current cookie"
	case errors.Is(err, session.ErrUnauthenticated), errors.As(err, &securityError):
		return http.StatusUnauthorized, identityapi.ProblemCodeUNAUTHENTICATED,
			"Unauthenticated", "Authentication required"
	case errors.Is(err, account.ErrInvalidToken):
		return http.StatusBadRequest,
			identityapi.ProblemCodeINVALIDTOKEN,
			"Invalid token",
			"Token is invalid, expired or already used"
	case errors.Is(err, auth.ErrEmailNotVerified):
		return http.StatusForbidden,
			identityapi.ProblemCodeEMAILNOTVERIFIED,
			"Email not verified",
			"Confirm your email before signing in"
	case errors.Is(err, auth.ErrInvalidCredentials):
		return http.StatusUnauthorized, identityapi.ProblemCodeINVALIDCREDENTIALS,
			"Invalid credentials", "Invalid email or password"
	case errors.Is(err, domain.ErrEmailAlreadyRegistered):
		return http.StatusConflict, identityapi.ProblemCodeREGISTRATIONCONFLICT,
			"Registration conflict", "Unable to register this account"
	case errors.Is(err, domain.ErrInvalidEmail), errors.Is(err, password.ErrInvalidPassword):
		return http.StatusBadRequest, identityapi.ProblemCodeINVALIDREQUEST,
			"Invalid request", "Email or password does not satisfy registration requirements"
	default:
		return http.StatusInternalServerError, identityapi.ProblemCodeINTERNALERROR,
			"Internal server error", "An unexpected error occurred"
	}
}

func (h *Handler) decodeError(
	ctx context.Context,
	w http.ResponseWriter,
	_ *http.Request,
	err error,
) {
	var maxBytes *http.MaxBytesError
	var decodeParams *ogenerrors.DecodeParamsError
	var decodeRequest *ogenerrors.DecodeRequestError
	switch {
	case errors.As(err, &maxBytes):
		h.writeProblem(w, problemFor(ctx, http.StatusRequestEntityTooLarge, identityapi.ProblemCodePAYLOADTOOLARGE,
			"Payload too large", "Request body exceeds 4 KiB"))
	case errors.As(err, &decodeParams), errors.As(err, &decodeRequest):
		h.writeProblem(w, problemFor(ctx, http.StatusBadRequest, identityapi.ProblemCodeINVALIDREQUEST,
			"Invalid request", "Request could not be decoded"))
	default:
		h.writeProblem(w, h.NewError(ctx, err))
	}
}

func (h *Handler) notFound(w http.ResponseWriter, r *http.Request) {
	h.writeProblem(w, problemFor(r.Context(), http.StatusNotFound, identityapi.ProblemCodeROUTENOTFOUND,
		"Route not found", "Route not found"))
}

func (h *Handler) methodNotAllowed(w http.ResponseWriter, r *http.Request, allowed string) {
	w.Header().Set("Allow", allowed)
	h.writeProblem(w, problemFor(r.Context(), http.StatusMethodNotAllowed, identityapi.ProblemCodeMETHODNOTALLOWED,
		"Method not allowed", "Method not allowed"))
}

func (h *Handler) writeProblem(w http.ResponseWriter, problem *identityapi.ProblemStatusCodeWithHeaders) {
	body, err := json.Marshal(&problem.Response, jsontext.EscapeForHTML(true))
	if err != nil {
		h.log.Error("encode Identity Problem failed", zap.String("request_id", problem.XRequestID))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("X-Request-ID", problem.XRequestID)
	if value, ok := problem.RetryAfter.Get(); ok {
		w.Header().Set("Retry-After", value)
	}
	w.WriteHeader(problem.StatusCode)
	if _, err := w.Write(body); err != nil { //nolint:gosec // G705: HTML-escaped Problem JSON, not HTML.
		h.log.Error("write Identity Problem failed", zap.String("request_id", problem.XRequestID))
	}
}
