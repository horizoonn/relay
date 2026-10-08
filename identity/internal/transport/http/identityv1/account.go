package identityv1

import (
	"context"

	"github.com/horizoonn/relay/platform/pkg/httpmiddleware"
	identityapi "github.com/horizoonn/relay/shared/pkg/openapi/identity/v1"
)

func (h *Handler) RequestEmailVerification(
	ctx context.Context,
	req *identityapi.EmailRequest,
	_ identityapi.RequestEmailVerificationParams,
) (identityapi.RequestEmailVerificationRes, error) {
	if err := h.requests.RequestVerification(ctx, req.Email); err != nil {
		return nil, err
	}
	return &identityapi.RequestEmailVerificationAccepted{
		XRequestID: httpmiddleware.RequestID(ctx),
	}, nil
}

func (h *Handler) RequestPasswordReset(
	ctx context.Context,
	req *identityapi.EmailRequest,
	_ identityapi.RequestPasswordResetParams,
) (identityapi.RequestPasswordResetRes, error) {
	if err := h.requests.RequestPasswordReset(ctx, req.Email); err != nil {
		return nil, err
	}
	return &identityapi.RequestPasswordResetAccepted{
		XRequestID: httpmiddleware.RequestID(ctx),
	}, nil
}

func (h *Handler) VerifyEmail(
	ctx context.Context,
	req *identityapi.AccountToken,
	_ identityapi.VerifyEmailParams,
) (identityapi.VerifyEmailRes, error) {
	if err := h.account.VerifyEmail(ctx, req.Token); err != nil {
		return nil, err
	}
	return &identityapi.VerifyEmailNoContent{
		XRequestID: httpmiddleware.RequestID(ctx),
	}, nil
}

func (h *Handler) ResetPassword(
	ctx context.Context,
	req *identityapi.PasswordReset,
	_ identityapi.ResetPasswordParams,
) (identityapi.ResetPasswordRes, error) {
	if err := h.account.ResetPassword(ctx, req.Token, req.Password); err != nil {
		return nil, err
	}
	return &identityapi.ResetPasswordNoContent{
		XRequestID: httpmiddleware.RequestID(ctx),
		SetCookie:  clearSessionCookies(),
	}, nil
}
