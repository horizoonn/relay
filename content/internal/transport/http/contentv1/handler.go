package contentv1

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/horizoonn/relay/platform/pkg/httpmiddleware"
	contentapi "github.com/horizoonn/relay/shared/pkg/openapi/content/v1"
	"go.uber.org/zap"

	captureusecase "github.com/horizoonn/relay/content/internal/usecase/capture"
	collectionusecase "github.com/horizoonn/relay/content/internal/usecase/collection"
	itemusecase "github.com/horizoonn/relay/content/internal/usecase/item"
	searchusecase "github.com/horizoonn/relay/content/internal/usecase/search"
)

type Handler struct {
	capture    *captureusecase.Service
	item       *itemusecase.Service
	collection *collectionusecase.Service
	search     *searchusecase.Service
	cursors    *CursorCodec
	log        *zap.Logger
}

func NewHandler(
	capture *captureusecase.Service,
	item *itemusecase.Service,
	collection *collectionusecase.Service,
	search *searchusecase.Service,
	cursors *CursorCodec,
	log *zap.Logger,
) (*Handler, error) {
	handler := &Handler{
		capture:    capture,
		item:       item,
		collection: collection,
		search:     search,
		cursors:    cursors,
		log:        log,
	}
	if err := handler.validate(); err != nil {
		return nil, err
	}
	return handler, nil
}

func (h *Handler) validate() error {
	if h == nil || h.capture == nil || h.item == nil ||
		h.collection == nil || h.search == nil || h.cursors == nil || h.log == nil {
		return errors.New("content HTTP handler requires all use cases, cursor codec and logger")
	}
	return nil
}

var _ contentapi.Handler = (*Handler)(nil)

func NewServer(
	handler *Handler,
	verifier AccessVerifier,
	allowedOrigin string,
	limiter RateLimiter,
) (http.Handler, error) {
	if err := handler.validate(); err != nil {
		return nil, err
	}
	if verifier == nil || limiter == nil {
		return nil, errors.New("content access verifier and rate limiter are required")
	}
	if err := validateOrigin(allowedOrigin); err != nil {
		return nil, err
	}
	server, err := contentapi.NewServer(handler, NewSecurity(verifier, allowedOrigin),
		contentapi.WithMiddleware(rateLimitMiddleware(limiter)),
		contentapi.WithErrorHandler(handler.decodeError),
		contentapi.WithNotFound(handler.notFound),
		contentapi.WithMethodNotAllowed(handler.methodNotAllowed),
	)
	if err != nil {
		return nil, fmt.Errorf("create Content API server: %w", err)
	}
	protected := handler.browserSecurity(bodyLimitMiddleware(server))
	recovered := httpmiddleware.Recovery(handler.log, protected, func(w http.ResponseWriter, r *http.Request) {
		handler.writeProblem(w, problemFor(r.Context(), http.StatusInternalServerError,
			contentapi.ProblemCodeINTERNALERROR, "Internal server error", "An unexpected error occurred"))
	})
	return requestIDMiddleware(recovered), nil
}

func validateOrigin(allowedOrigin string) error {
	origin, err := url.Parse(allowedOrigin)
	if err != nil || origin == nil || origin.Scheme != "https" ||
		origin.Hostname() == "" || origin.User != nil || origin.Path != "" ||
		origin.RawQuery != "" || origin.ForceQuery || origin.Fragment != "" ||
		origin.Opaque != "" || origin.String() != allowedOrigin {
		return errors.New("invalid allowed content origin")
	}
	return nil
}
