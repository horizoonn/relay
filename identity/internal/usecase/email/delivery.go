package email

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/url"
	"time"
	"uuid"

	"github.com/horizoonn/relay/identity/internal/domain"
	"github.com/horizoonn/relay/identity/internal/secret"
)

type Delivery struct {
	queue  MailQueue
	users  DeliveryUsers
	tokens DeliveryTokens
	tx     Transactor
	cipher PayloadOpener
	sender Sender
	origin string
}

func NewDelivery(
	queue MailQueue,
	users DeliveryUsers,
	tokens DeliveryTokens,
	tx Transactor,
	cipher PayloadOpener,
	sender Sender,
	origin string,
) (*Delivery, error) {
	if queue == nil || users == nil || tokens == nil || tx == nil || cipher == nil || sender == nil {
		return nil, errors.New("email delivery requires all dependencies")
	}
	parsed, err := url.Parse(origin)
	if err != nil ||
		parsed.Scheme != "https" ||
		parsed.Host == "" ||
		parsed.User != nil ||
		parsed.Path != "" ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" {
		return nil, errors.New("email links require a configured HTTPS origin")
	}
	return &Delivery{
		queue:  queue,
		users:  users,
		tokens: tokens,
		tx:     tx,
		cipher: cipher,
		sender: sender,
		origin: origin,
	}, nil
}

func (d *Delivery) DeliverOne(ctx context.Context) (bool, error) {
	job, err := d.queue.Claim(ctx, time.Now().UTC())
	if errors.Is(err, domain.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("load next email delivery: %w", err)
	}
	err = d.deliver(ctx, job)
	if err == nil {
		if deleteErr := d.queue.Delete(ctx, job); deleteErr != nil {
			return true, fmt.Errorf("complete email delivery: %w", deleteErr)
		}
		return true, nil
	}
	if ctx.Err() != nil {
		return true, fmt.Errorf("deliver email: %w", ctx.Err())
	}
	var failure DeliveryFailure
	if errors.Is(err, ErrInvalidMailJob) || (errors.As(err, &failure) && failure.Permanent()) {
		if deleteErr := d.queue.Delete(ctx, job); deleteErr != nil {
			return true, errors.Join(err, fmt.Errorf("discard email job: %w", deleteErr))
		}
		return true, err
	}
	delay := time.Second * time.Duration(1<<min(max(job.Attempts-1, 0), 8))
	if retryErr := d.queue.Retry(ctx, job, time.Now().UTC().Add(delay)); retryErr != nil {
		return true, errors.Join(err, fmt.Errorf("retry email job: %w", retryErr))
	}
	return true, err
}

func (d *Delivery) deliver(ctx context.Context, job MailJob) error {
	if !time.Now().UTC().Before(job.ExpiresAt) || job.Attempts > 24 {
		return nil
	}
	payload, hash, err := d.decodePayload(job.EncryptedPayload)
	if err != nil {
		return err
	}
	email := payload.Email
	if payload.Purpose == passwordChangedMail {
		return d.deliverNotice(ctx, job, payload)
	}
	if job.PreparedUserID == uuid.Nil() {
		if prepareErr := d.prepare(ctx, job, payload, hash); prepareErr != nil {
			if errors.Is(prepareErr, domain.ErrNotFound) {
				return nil
			}
			return fmt.Errorf("prepare account email: %w", prepareErr)
		}
	}
	token, err := d.tokens.Get(ctx, hash)
	if errors.Is(err, domain.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("load email account token: %w", err)
	}
	if err := token.Validate(); err != nil {
		return fmt.Errorf("validate email account token: %w", err)
	}
	if !matchesMailJob(token, job, domain.AccountTokenPurpose(payload.Purpose), hash) {
		return nil
	}
	path, subject := "/verify-email", "Confirm your Relay email"
	if payload.Purpose == string(domain.ResetPassword) {
		path, subject = "/reset-password", "Reset your Relay password"
	}
	link := d.origin + path + "#token=" + url.QueryEscape(payload.Token)
	if err := d.sender.Send(ctx, Mail{
		ID:        job.ID,
		CreatedAt: job.CreatedAt,
		To:        email,
		Subject:   subject,
		Body: "Open this link in Relay to continue:\r\n" + link +
			"\r\n\r\nIf you did not request this, ignore this message.\r\n",
	}); err != nil {
		return fmt.Errorf("send account email: %w", err)
	}
	return nil
}

func (d *Delivery) prepare(
	ctx context.Context,
	job MailJob,
	payload mailPayload,
	hash [32]byte,
) error {
	return d.tx.WithinTransaction(ctx, func(ctx context.Context) error {
		initial, err := d.users.GetByEmail(ctx, payload.Email)
		if err != nil {
			return fmt.Errorf("load email recipient: %w", err)
		}
		user, err := d.users.GetForUpdate(ctx, initial.ID)
		if err != nil {
			return fmt.Errorf("lock email recipient: %w", err)
		}
		if err := user.Validate(); err != nil {
			return fmt.Errorf("validate email recipient: %w", err)
		}
		if user.State != domain.UserActive ||
			user.Email != payload.Email ||
			(payload.Purpose == string(domain.VerifyEmail) &&
				user.EmailVerifiedAt != nil) {
			return domain.ErrNotFound
		}
		if payload.Purpose == string(domain.ResetPassword) {
			changedAt, err := d.users.GetPasswordUpdatedAt(ctx, user.ID)
			if err != nil {
				return fmt.Errorf("load recipient password change time: %w", err)
			}
			if changedAt.After(job.CreatedAt) {
				return domain.ErrNotFound
			}
		}
		token := domain.AccountToken{
			Hash:      hash,
			UserID:    user.ID,
			Purpose:   domain.AccountTokenPurpose(payload.Purpose),
			CreatedAt: job.CreatedAt,
			ExpiresAt: job.ExpiresAt,
		}
		if err := token.Validate(); err != nil {
			return fmt.Errorf("validate prepared account token: %w", err)
		}
		if err := d.tokens.Create(ctx, token); err != nil {
			return fmt.Errorf("persist email account token: %w", err)
		}
		if err := d.queue.MarkPrepared(ctx, job, user); err != nil {
			return fmt.Errorf("mark email delivery prepared: %w", err)
		}
		return nil
	})
}

func (d *Delivery) decodePayload(encrypted []byte) (mailPayload, [32]byte, error) {
	plain, err := d.cipher.Open(encrypted)
	if err != nil {
		return mailPayload{}, [32]byte{}, ErrInvalidMailJob
	}
	var payload mailPayload
	if json.Unmarshal(plain, &payload) != nil ||
		(domain.AccountTokenPurpose(payload.Purpose).Lifetime() == 0 &&
			payload.Purpose != passwordChangedMail) {
		return mailPayload{}, [32]byte{}, ErrInvalidMailJob
	}
	email, err := domain.NormalizeEmail(payload.Email)
	if err != nil || email != payload.Email {
		return mailPayload{}, [32]byte{}, ErrInvalidMailJob
	}
	if payload.Purpose == passwordChangedMail {
		if payload.Token != "" {
			return mailPayload{}, [32]byte{}, ErrInvalidMailJob
		}
		return payload, [32]byte{}, nil
	}
	hash, err := secret.Digest(payload.Token)
	if err != nil {
		return mailPayload{}, [32]byte{}, ErrInvalidMailJob
	}

	return payload, hash, nil
}

func matchesMailJob(
	token domain.AccountToken,
	job MailJob,
	purpose domain.AccountTokenPurpose,
	hash [32]byte,
) bool {
	return token.Hash == hash &&
		token.Purpose == purpose &&
		token.CreatedAt.Equal(job.CreatedAt) &&
		token.ExpiresAt.Equal(job.ExpiresAt) &&
		(job.PreparedUserID == uuid.Nil() || token.UserID == job.PreparedUserID) &&
		token.Active(time.Now().UTC())
}

func (d *Delivery) deliverNotice(
	ctx context.Context,
	job MailJob,
	payload mailPayload,
) error {
	user, err := d.users.GetByEmail(ctx, payload.Email)
	if errors.Is(err, domain.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("load password change recipient: %w", err)
	}
	if err := user.Validate(); err != nil {
		return fmt.Errorf("validate password change recipient: %w", err)
	}
	if user.Email != payload.Email {
		return ErrInvalidMailJob
	}
	if err := d.sender.Send(ctx, Mail{
		ID:        job.ID,
		CreatedAt: job.CreatedAt,
		To:        payload.Email,
		Subject:   "Your Relay password was changed",
		Body: "Your Relay password was changed. All existing sessions were revoked.\r\n\r\n" +
			"If you did not make this change, use password recovery in Relay " +
			"and contact the administrator.\r\n",
	}); err != nil {
		return fmt.Errorf("send password change notice: %w", err)
	}
	return nil
}
