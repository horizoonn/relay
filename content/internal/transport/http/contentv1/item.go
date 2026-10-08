package contentv1

import (
	"context"
	"uuid"

	"github.com/horizoonn/relay/platform/pkg/httpmiddleware"
	contentapi "github.com/horizoonn/relay/shared/pkg/openapi/content/v1"

	"github.com/horizoonn/relay/content/internal/domain"
	itemusecase "github.com/horizoonn/relay/content/internal/usecase/item"
)

func (h *Handler) GetItem(
	ctx context.Context,
	params contentapi.GetItemParams,
) (contentapi.GetItemRes, error) {
	owner, err := PrincipalFromContext(ctx)
	if err != nil {
		return nil, err
	}
	item, err := h.item.Get(ctx, owner, uuid.UUID(params.ItemID))
	if err != nil {
		return nil, err
	}
	apiItem, err := toAPIItem(item)
	if err != nil {
		return nil, err
	}
	return &contentapi.ItemHeaders{
		AcceptPatch: contentapi.AcceptPatchApplicationMergePatchJSON,
		XRequestID:  httpmiddleware.RequestID(ctx),
		Response:    apiItem,
	}, nil
}

func (h *Handler) PatchItem(
	ctx context.Context,
	req *contentapi.ItemPatch,
	params contentapi.PatchItemParams,
) (contentapi.PatchItemRes, error) {
	owner, err := PrincipalFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, itemusecase.ErrInvalidRequest
	}
	command := itemusecase.PatchCommand{
		OwnerID: owner,
		ItemID:  uuid.UUID(params.ItemID),
	}
	if value, ok := req.Keep.Get(); ok {
		command.Keep = &value
	}
	if value, ok := req.ReviewStatus.Get(); ok {
		status := domain.ReviewStatus(value)
		command.ReviewStatus = &status
	}
	if req.DisplayTitle.Set {
		command.DisplayTitle.Present = true
		if !req.DisplayTitle.Null {
			value := req.DisplayTitle.Value
			command.DisplayTitle.Value = &value
		}
	}
	item, err := h.item.Patch(ctx, command)
	if err != nil {
		return nil, err
	}
	apiItem, err := toAPIItem(item)
	if err != nil {
		return nil, err
	}
	return &contentapi.ItemHeaders{
		AcceptPatch: contentapi.AcceptPatchApplicationMergePatchJSON,
		XRequestID:  httpmiddleware.RequestID(ctx),
		Response:    apiItem,
	}, nil
}

func (h *Handler) DeleteItem(
	ctx context.Context,
	params contentapi.DeleteItemParams,
) (contentapi.DeleteItemRes, error) {
	owner, err := PrincipalFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.item.Delete(ctx, owner, uuid.UUID(params.ItemID)); err != nil {
		return nil, err
	}
	return &contentapi.DeleteItemNoContent{
		XRequestID: httpmiddleware.RequestID(ctx),
	}, nil
}
