package contentv1

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"uuid"

	contentapi "github.com/horizoonn/relay/shared/pkg/openapi/content/v1"
	"github.com/ogen-go/ogen/ogenerrors"
	"github.com/ogen-go/ogen/validate"

	"github.com/horizoonn/relay/content/internal/auth"
	"github.com/horizoonn/relay/content/internal/domain"
	captureusecase "github.com/horizoonn/relay/content/internal/usecase/capture"
	collectionusecase "github.com/horizoonn/relay/content/internal/usecase/collection"
	itemusecase "github.com/horizoonn/relay/content/internal/usecase/item"
	searchusecase "github.com/horizoonn/relay/content/internal/usecase/search"
)

func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

func problemFor(
	ctx context.Context,
	status int,
	code contentapi.ProblemCode,
	title, detail string,
) *contentapi.ProblemStatusCodeWithHeaders {
	id := requestID(ctx)
	if id == "" {
		id = uuid.New().String()
	}
	typ := url.URL{
		Scheme: "urn",
		Opaque: "relay:problem:" + strings.ToLower(strings.ReplaceAll(string(code), "_", "-")),
	}
	return &contentapi.ProblemStatusCodeWithHeaders{
		StatusCode: status,
		XRequestID: id,
		Response: contentapi.Problem{
			Type:      typ,
			Title:     title,
			Status:    status,
			Code:      code,
			Detail:    detail,
			RequestID: id,
		},
	}
}

func (h *Handler) NewError(
	ctx context.Context,
	err error,
) *contentapi.ProblemStatusCodeWithHeaders {
	status, code, title, detail := describeError(ctx, err)
	if status >= http.StatusInternalServerError {
		h.log.ErrorContext(
			ctx,
			"content HTTP request failed",
			"status",
			status,
			"request_id",
			requestID(ctx),
			"error",
			err,
		)
	}
	return problemFor(ctx, status, code, title, detail)
}

func describeError(
	ctx context.Context,
	err error,
) (int, contentapi.ProblemCode, string, string) {
	var securityErr *ogenerrors.SecurityError
	switch {
	case errors.Is(err, auth.ErrIdentityUnavailable):
		return http.StatusServiceUnavailable,
			contentapi.ProblemCodeSERVICEUNAVAILABLE,
			"Service unavailable",
			"Identity is temporarily unavailable"
	case errors.Is(err, auth.ErrForbidden):
		return http.StatusForbidden,
			contentapi.ProblemCodeFORBIDDEN,
			"Forbidden",
			"CSRF validation failed"
	case errors.Is(err, auth.ErrUnauthenticated):
		return http.StatusUnauthorized,
			contentapi.ProblemCodeUNAUTHENTICATED,
			"Unauthenticated",
			"Authentication is required"
	case errors.As(err, &securityErr):
		if _, e := PrincipalFromContext(ctx); e == nil {
			return http.StatusForbidden,
				contentapi.ProblemCodeFORBIDDEN,
				"Forbidden",
				"CSRF validation failed"
		}
		return http.StatusUnauthorized,
			contentapi.ProblemCodeUNAUTHENTICATED,
			"Unauthenticated",
			"Authentication is required"
	case errors.Is(err, itemusecase.ErrItemNotFound):
		return http.StatusNotFound,
			contentapi.ProblemCodeITEMNOTFOUND,
			"Item not found",
			"Item not found"
	case errors.Is(err, captureusecase.ErrIdempotencyKeyReused):
		return http.StatusConflict,
			contentapi.ProblemCodeIDEMPOTENCYKEYREUSED,
			"Idempotency key reused",
			"Idempotency key was used for a different request"
	case errors.Is(err, captureusecase.ErrInvalidCommand), errors.Is(err, itemusecase.ErrInvalidRequest),
		errors.Is(err, collectionusecase.ErrInvalidQuery), errors.Is(err, searchusecase.ErrInvalidQuery),
		errors.Is(err, domain.ErrInvalidItem), errors.Is(err, domain.ErrInvalidSource),
		errors.Is(err, domain.ErrInvalidReviewStatus), errors.Is(err, domain.ErrInvalidDisplayTitle),
		errors.Is(err, ErrInvalidCursor):
		return http.StatusBadRequest,
			contentapi.ProblemCodeINVALIDREQUEST,
			"Invalid request",
			"Request validation failed"
	default:
		return http.StatusInternalServerError,
			contentapi.ProblemCodeINTERNALERROR,
			"Internal server error",
			"An unexpected error occurred"
	}
}

func (h *Handler) decodeError(
	ctx context.Context,
	w http.ResponseWriter,
	_ *http.Request,
	err error,
) {
	var maxBytes *http.MaxBytesError
	var invalidContentType *validate.InvalidContentTypeError
	var decodeParams *ogenerrors.DecodeParamsError
	var decodeRequest *ogenerrors.DecodeRequestError
	switch {
	case errors.As(err, &maxBytes):
		h.writeProblem(w, problemFor(ctx,
			http.StatusRequestEntityTooLarge,
			contentapi.ProblemCodePAYLOADTOOLARGE,
			"Payload too large",
			"Request body exceeds 512 KiB",
		))
	case errors.As(err, &invalidContentType):
		h.writeProblem(w, problemFor(ctx,
			http.StatusUnsupportedMediaType,
			contentapi.ProblemCodeUNSUPPORTEDMEDIATYPE,
			"Unsupported media type",
			"Unsupported Content-Type",
		))
	case errors.As(err, &decodeParams), errors.As(err, &decodeRequest):
		h.writeProblem(w, problemFor(ctx,
			http.StatusBadRequest,
			contentapi.ProblemCodeINVALIDREQUEST,
			"Invalid request",
			"Request could not be decoded",
		))
	default:
		h.log.ErrorContext(
			ctx,
			"content HTTP server error",
			"request_id",
			requestID(ctx),
			"error",
			err,
		)
		h.writeProblem(w, problemFor(ctx,
			http.StatusInternalServerError,
			contentapi.ProblemCodeINTERNALERROR,
			"Internal server error",
			"An unexpected error occurred",
		))
	}
}

func (h *Handler) notFound(w http.ResponseWriter, r *http.Request) {
	h.writeProblem(w, problemFor(
		r.Context(),
		http.StatusNotFound,
		contentapi.ProblemCodeROUTENOTFOUND,
		"Route not found",
		"Route not found",
	))
}

func (h *Handler) methodNotAllowed(
	w http.ResponseWriter,
	r *http.Request,
	allowed string,
) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", allowed)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Allow", allowed)
	h.writeProblem(w, problemFor(
		r.Context(),
		http.StatusMethodNotAllowed,
		contentapi.ProblemCodeMETHODNOTALLOWED,
		"Method not allowed",
		"Method not allowed",
	))
}

func (h *Handler) writeProblem(
	w http.ResponseWriter,
	p *contentapi.ProblemStatusCodeWithHeaders,
) {
	body, err := json.Marshal(&p.Response)
	if err != nil {
		h.log.Error(
			"encode Content Problem failed",
			"request_id",
			p.XRequestID,
			"error",
			err,
		)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("X-Request-ID", p.XRequestID)
	w.WriteHeader(p.StatusCode)
	if _, err := w.Write(body); err != nil {
		h.log.Error(
			"write Content Problem failed",
			"request_id",
			p.XRequestID,
			"error",
			err,
		)
	}
}
