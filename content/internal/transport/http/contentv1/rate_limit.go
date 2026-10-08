package contentv1

import (
	"context"
	"errors"

	"github.com/horizoonn/relay/platform/pkg/httpmiddleware"
	contentapi "github.com/horizoonn/relay/shared/pkg/openapi/content/v1"
	"github.com/ogen-go/ogen/middleware"

	contentlimit "github.com/horizoonn/relay/content/internal/ratelimit"
)

type RateLimiter interface {
	Allow(context.Context, contentlimit.Scope, string) error
}

func rateLimitMiddleware(limiter RateLimiter) middleware.Middleware {
	return func(req middleware.Request, next middleware.Next) (middleware.Response, error) {
		httpmiddleware.SetOperation(req.Context, req.OperationName)
		owner, err := PrincipalFromContext(req.Context)
		if err != nil {
			return middleware.Response{}, err
		}
		scope, err := rateLimitScope(req.OperationName)
		if err != nil {
			return middleware.Response{}, err
		}
		if err := limiter.Allow(req.Context, scope, owner.String()); err != nil {
			return middleware.Response{}, err
		}
		return next(req)
	}
}

func rateLimitScope(operation string) (contentlimit.Scope, error) {
	switch operation {
	case contentapi.CaptureItemOperation:
		return contentlimit.Capture, nil
	case contentapi.PatchItemOperation, contentapi.DeleteItemOperation:
		return contentlimit.Write, nil
	case contentapi.GetItemOperation, contentapi.ListRecentItemsOperation,
		contentapi.ListLibraryItemsOperation, contentapi.ListLaterItemsOperation:
		return contentlimit.Read, nil
	case contentapi.SearchItemsOperation:
		return contentlimit.Search, nil
	default:
		return "", errors.New("missing Content rate limit policy")
	}
}
