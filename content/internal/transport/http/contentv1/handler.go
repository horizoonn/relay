package contentv1

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"

	contentapi "github.com/horizoonn/relay/shared/pkg/openapi/content/v1"

	"github.com/horizoonn/relay/content/internal/auth"
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
	log        *slog.Logger
}

func NewHandler(
	capture *captureusecase.Service,
	item *itemusecase.Service,
	collection *collectionusecase.Service,
	search *searchusecase.Service,
	cursors *CursorCodec,
	log *slog.Logger,
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
	auth auth.Authenticator,
	allowedOrigin string,
) (http.Handler, error) {
	if err := handler.validate(); err != nil {
		return nil, err
	}
	if auth == nil {
		return nil, errors.New("content authenticator is required")
	}
	origin, err := url.Parse(allowedOrigin)
	if err != nil || origin == nil || (origin.Scheme != "http" && origin.Scheme != "https") ||
		origin.Hostname() == "" || origin.User != nil || origin.Path != "" ||
		origin.RawQuery != "" || origin.Fragment != "" || origin.String() != allowedOrigin {
		return nil, errors.New("invalid allowed content origin")
	}
	server, err := contentapi.NewServer(handler, NewSecurity(auth, allowedOrigin),
		contentapi.WithErrorHandler(handler.decodeError),
		contentapi.WithNotFound(handler.notFound),
		contentapi.WithMethodNotAllowed(handler.methodNotAllowed),
	)
	if err != nil {
		return nil, err
	}
	return requestIDMiddleware(bodyLimitMiddleware(server)), nil
}
