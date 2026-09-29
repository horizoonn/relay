package contentv1

import (
	"context"
	"strings"

	contentapi "github.com/horizoonn/relay/shared/pkg/openapi/content/v1"

	"github.com/horizoonn/relay/content/internal/usecase/search"
)

func (h *Handler) SearchItems(
	ctx context.Context,
	params contentapi.SearchItemsParams,
) (contentapi.SearchItemsRes, error) {
	owner, err := PrincipalFromContext(ctx)
	if err != nil {
		return nil, err
	}
	query := strings.TrimSpace(params.Q)
	request := search.Params{
		OwnerID: owner,
		Query:   query,
		Limit:   params.Limit.Or(20),
	}
	if cursor, ok := params.Cursor.Get(); ok {
		anchor, decodeErr := h.cursors.DecodeSearch(cursor, owner, query)
		if decodeErr != nil {
			return nil, decodeErr
		}
		request.After = &anchor
	}
	page, err := h.search.Search(ctx, request)
	if err != nil {
		return nil, err
	}
	items := make([]contentapi.ItemSummary, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, toAPISummary(item))
	}
	response := contentapi.ItemPage{
		Items: items,
	}
	if page.Next != nil {
		cursor, err := h.cursors.EncodeSearch(owner, query, *page.Next)
		if err != nil {
			return nil, err
		}
		response.NextCursor = contentapi.NewOptString(cursor)
	}
	return &contentapi.ItemPageHeaders{
		XRequestID: requestID(ctx),
		Response:   response,
	}, nil
}
