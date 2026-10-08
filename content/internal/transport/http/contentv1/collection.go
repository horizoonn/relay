package contentv1

import (
	"context"
	"fmt"
	"uuid"

	"github.com/horizoonn/relay/platform/pkg/httpmiddleware"
	contentapi "github.com/horizoonn/relay/shared/pkg/openapi/content/v1"

	"github.com/horizoonn/relay/content/internal/usecase/collection"
)

func (h *Handler) ListRecentItems(
	ctx context.Context,
	params contentapi.ListRecentItemsParams,
) (contentapi.ListRecentItemsRes, error) {
	page, err := h.listCollection(ctx, "recent", params.Limit.Or(20), params.Cursor)
	if err != nil {
		return nil, err
	}
	return page, nil
}

func (h *Handler) ListLibraryItems(
	ctx context.Context,
	params contentapi.ListLibraryItemsParams,
) (contentapi.ListLibraryItemsRes, error) {
	page, err := h.listCollection(ctx, "library", params.Limit.Or(20), params.Cursor)
	if err != nil {
		return nil, err
	}
	return page, nil
}

func (h *Handler) ListLaterItems(
	ctx context.Context,
	params contentapi.ListLaterItemsParams,
) (contentapi.ListLaterItemsRes, error) {
	page, err := h.listCollection(ctx, "later", params.Limit.Or(20), params.Cursor)
	if err != nil {
		return nil, err
	}
	return page, nil
}

func (h *Handler) listCollection(
	ctx context.Context,
	surface string,
	limit int,
	cursor contentapi.OptString,
) (*contentapi.ItemPageHeaders, error) {
	owner, err := PrincipalFromContext(ctx)
	if err != nil {
		return nil, err
	}
	params := collection.ListParams{
		OwnerID: owner,
		Limit:   limit,
	}
	if value, ok := cursor.Get(); ok {
		anchor, decodeErr := h.cursors.DecodeCollection(value, owner, surface)
		if decodeErr != nil {
			return nil, decodeErr
		}
		params.After = &anchor
	}
	var page collection.Page
	switch surface {
	case "recent":
		page, err = h.collection.ListRecent(ctx, params)
	case "library":
		page, err = h.collection.ListLibrary(ctx, params)
	case "later":
		page, err = h.collection.ListLater(ctx, params)
	default:
		return nil, fmt.Errorf("unsupported collection surface %q", surface)
	}
	if err != nil {
		return nil, err
	}
	return collectionPage(owner, surface, page, h.cursors, httpmiddleware.RequestID(ctx))
}

func collectionPage(
	owner uuid.UUID,
	surface string,
	page collection.Page,
	codec *CursorCodec,
	id string,
) (*contentapi.ItemPageHeaders, error) {
	items := make([]contentapi.ItemSummary, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, toAPISummary(item))
	}
	response := contentapi.ItemPage{
		Items: items,
	}
	if page.Next != nil {
		cursor, err := codec.EncodeCollection(owner, surface, *page.Next)
		if err != nil {
			return nil, err
		}
		response.NextCursor = contentapi.NewOptString(cursor)
	}
	return &contentapi.ItemPageHeaders{
		XRequestID: id,
		Response:   response,
	}, nil
}
