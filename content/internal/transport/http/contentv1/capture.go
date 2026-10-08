package contentv1

import (
	"context"
	"fmt"

	"github.com/horizoonn/relay/platform/pkg/httpmiddleware"
	contentapi "github.com/horizoonn/relay/shared/pkg/openapi/content/v1"

	"github.com/horizoonn/relay/content/internal/domain"
	captureusecase "github.com/horizoonn/relay/content/internal/usecase/capture"
)

func (h *Handler) CaptureItem(
	ctx context.Context,
	req contentapi.CaptureRequest,
	params contentapi.CaptureItemParams,
) (contentapi.CaptureItemRes, error) {
	owner, err := PrincipalFromContext(ctx)
	if err != nil {
		return nil, err
	}
	command := captureusecase.Command{
		OwnerID:        owner,
		IdempotencyKey: params.IdempotencyKey,
	}
	switch req.Type {
	case contentapi.URLCaptureRequestCaptureRequest:
		command.SourceType = domain.SourceURL
		command.URL = req.URLCaptureRequest.URL
		command.Keep = req.URLCaptureRequest.Keep.Or(false)
		command.Later = req.URLCaptureRequest.Later.Or(false)
	case contentapi.TextCaptureRequestCaptureRequest:
		command.SourceType = domain.SourceText
		command.Text = req.TextCaptureRequest.Text
		command.Keep = req.TextCaptureRequest.Keep.Or(false)
		command.Later = req.TextCaptureRequest.Later.Or(false)
	default:
		return nil, captureusecase.ErrInvalidCommand
	}
	result, err := h.capture.Capture(ctx, command)
	if err != nil {
		return nil, err
	}
	switch result.Outcome {
	case captureusecase.OutcomeCreated:
		return &contentapi.CreatedCaptureReceiptHeaders{
			Location:   fmt.Sprintf("/api/v1/items/%s", result.ItemID),
			XRequestID: httpmiddleware.RequestID(ctx),
			Response: contentapi.CreatedCaptureReceipt{
				ItemID:  contentapi.ItemID(result.ItemID),
				Outcome: contentapi.CreatedCaptureReceiptOutcomeCreated,
			},
		}, nil
	case captureusecase.OutcomeReused:
		return &contentapi.ReusedCaptureReceiptHeaders{
			XRequestID: httpmiddleware.RequestID(ctx),
			Response: contentapi.ReusedCaptureReceipt{
				ItemID:  contentapi.ItemID(result.ItemID),
				Outcome: contentapi.ReusedCaptureReceiptOutcomeReused,
			},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported capture outcome %q", result.Outcome)
	}
}
