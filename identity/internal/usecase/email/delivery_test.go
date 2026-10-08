package email_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"testing"
	"testing/synctest"
	"time"
	"uuid"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/horizoonn/relay/identity/internal/domain"
	"github.com/horizoonn/relay/identity/internal/secret"
	"github.com/horizoonn/relay/identity/internal/usecase/email"
	"github.com/horizoonn/relay/identity/internal/usecase/email/mocks"
)

type plaintextPayload struct{}

func (plaintextPayload) Open(value []byte) ([]byte, error) { return value, nil }

type directMailTransaction struct{}

func (directMailTransaction) WithinTransaction(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

type sendError struct{ permanent bool }

func (e *sendError) Error() string   { return "delivery failed" }
func (e *sendError) Permanent() bool { return e.permanent }

type deliveryFixture struct {
	delivery *email.Delivery
	queue    *mocks.MockMailQueue
	users    *mocks.MockDeliveryUsers
	tokens   *mocks.MockDeliveryTokens
	sender   *mocks.MockSender
	user     domain.User
	job      email.MailJob
}

func newNoticeDelivery(t *testing.T) deliveryFixture {
	t.Helper()
	now := time.Now().UTC()
	user, err := domain.NewUser("user@example.com", now)
	require.NoError(t, err)
	payload, err := json.Marshal(map[string]string{"Email": user.Email, "Purpose": "password_changed"})
	require.NoError(t, err)
	f := deliveryFixture{
		queue: mocks.NewMockMailQueue(t), users: mocks.NewMockDeliveryUsers(t),
		tokens: mocks.NewMockDeliveryTokens(t), sender: mocks.NewMockSender(t), user: user,
		job: email.MailJob{
			ID: uuid.NewV7(), EncryptedPayload: payload, CreatedAt: now,
			ExpiresAt: now.Add(time.Hour), LeaseToken: uuid.NewV7(), Attempts: 1,
		},
	}
	f.delivery, err = email.NewDelivery(f.queue, f.users, f.tokens, directMailTransaction{}, plaintextPayload{}, f.sender, "https://relay.example")
	require.NoError(t, err)
	return f
}

func (f deliveryFixture) expectNotice(t *testing.T, sendErr error) {
	t.Helper()
	f.users.EXPECT().GetByEmail(t.Context(), f.user.Email).Return(f.user, nil).Once()
	f.sender.EXPECT().Send(t.Context(), mock.MatchedBy(func(mail email.Mail) bool {
		return mail.ID == f.job.ID && mail.CreatedAt.Equal(f.job.CreatedAt) &&
			mail.To == f.user.Email && mail.Subject == "Your Relay password was changed" &&
			strings.Contains(mail.Body, "All existing sessions were revoked") && !strings.Contains(mail.Body, "#token=")
	})).Return(sendErr).Once()
}

func TestDeliverOne(t *testing.T) {
	temporary := &sendError{}
	permanent := &sendError{permanent: true}
	tests := []struct {
		name       string
		sendErr    error
		badPayload bool
		retryAfter time.Duration
		attempts   int
	}{
		{name: "success"},
		{name: "permanent recipient rejection", sendErr: permanent},
		{name: "temporary SMTP failure", sendErr: temporary, retryAfter: time.Second},
		{name: "wrapped permanent SMTP failure", sendErr: fmt.Errorf("SMTP DATA: %w", permanent)},
		{name: "wrapped temporary SMTP failure", sendErr: fmt.Errorf("SMTP connect: %w", temporary), retryAfter: time.Second},
		{name: "unclassified failure", sendErr: errors.New("delivery interrupted"), retryAfter: time.Second},
		{name: "corrupt payload", badPayload: true},
		{name: "second attempt backs off", sendErr: temporary, attempts: 2, retryAfter: 2 * time.Second},
		{name: "backoff is capped", sendErr: temporary, attempts: 24, retryAfter: 256 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				f := newNoticeDelivery(t)
				if tt.attempts != 0 {
					f.job.Attempts = tt.attempts
				}
				if tt.badPayload {
					f.job.EncryptedPayload = []byte("invalid JSON")
				} else {
					f.expectNotice(t, tt.sendErr)
				}
				now := time.Now().UTC()
				f.queue.EXPECT().Claim(t.Context(), now).Return(f.job, nil).Once()
				if tt.retryAfter != 0 {
					f.queue.EXPECT().Retry(t.Context(), f.job, now.Add(tt.retryAfter)).Return(nil).Once()
				} else {
					f.queue.EXPECT().Delete(t.Context(), f.job).Return(nil).Once()
				}
				worked, err := f.delivery.DeliverOne(t.Context())
				require.True(t, worked)
				if tt.badPayload {
					require.ErrorIs(t, err, email.ErrInvalidMailJob)
				} else {
					require.ErrorIs(t, err, tt.sendErr)
				}
			})
		})
	}
}

func TestDeliveryQueueErrors(t *testing.T) {
	storageErr := errors.New("queue unavailable")
	temporary := &sendError{}
	permanent := &sendError{permanent: true}
	tests := []struct {
		name    string
		sendErr error
		retry   bool
	}{
		{name: "complete successful delivery"},
		{name: "discard permanent failure", sendErr: permanent},
		{name: "reschedule temporary failure", sendErr: temporary, retry: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newNoticeDelivery(t)
				now := time.Now().UTC()
				f.queue.EXPECT().Claim(t.Context(), now).Return(f.job, nil).Once()
				f.expectNotice(t, tt.sendErr)
				if tt.retry {
					f.queue.EXPECT().Retry(t.Context(), f.job, now.Add(time.Second)).Return(storageErr).Once()
				} else {
					f.queue.EXPECT().Delete(t.Context(), f.job).Return(storageErr).Once()
				}
				worked, err := f.delivery.DeliverOne(t.Context())
				require.True(t, worked)
				require.ErrorIs(t, err, storageErr)
				if tt.sendErr != nil {
					require.ErrorIs(t, err, tt.sendErr)
				}
			})
		})
	}
}

func TestDeliveryClaimFailureDoesNotSend(t *testing.T) {
	storageErr := errors.New("claim failed")
	for _, tt := range []struct {
		name     string
		claimErr error
		wantErr  error
	}{
		{name: "empty queue", claimErr: domain.ErrNotFound},
		{name: "storage failure", claimErr: storageErr, wantErr: storageErr},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newNoticeDelivery(t)
				f.queue.EXPECT().Claim(t.Context(), time.Now().UTC()).Return(email.MailJob{}, tt.claimErr).Once()
				worked, err := f.delivery.DeliverOne(t.Context())
				require.False(t, worked)
				require.ErrorIs(t, err, tt.wantErr)
			})
		})
	}
}

func TestDeliveryPreparationRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newNoticeDelivery(t)
		raw, err := secret.Generate()
		require.NoError(t, err)
		hash, err := secret.Digest(raw)
		require.NoError(t, err)
		f.job.EncryptedPayload, err = json.Marshal(map[string]string{"Email": f.user.Email, "Purpose": string(domain.VerifyEmail), "Token": raw})
		require.NoError(t, err)
		failure := errors.New("mark prepared failed")
		now := time.Now().UTC()
		f.queue.EXPECT().Claim(t.Context(), now).Return(f.job, nil).Once()
		f.users.EXPECT().GetByEmail(t.Context(), f.user.Email).Return(f.user, nil).Once()
		f.users.EXPECT().GetForUpdate(t.Context(), f.user.ID).Return(f.user, nil).Once()
		f.tokens.EXPECT().Create(t.Context(), domain.AccountToken{
			Hash: hash, UserID: f.user.ID,
			Purpose: domain.VerifyEmail, CreatedAt: f.job.CreatedAt, ExpiresAt: f.job.ExpiresAt,
		}).Return(nil).Once()
		f.queue.EXPECT().MarkPrepared(t.Context(), f.job, f.user).Return(failure).Once()
		f.queue.EXPECT().Retry(t.Context(), f.job, now.Add(time.Second)).Return(nil).Once()
		worked, err := f.delivery.DeliverOne(t.Context())
		require.True(t, worked)
		require.ErrorIs(t, err, failure)
	})
}

func TestDeliveryCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newNoticeDelivery(t)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		f.queue.EXPECT().Claim(ctx, time.Now().UTC()).Return(f.job, nil).Once()
		f.users.EXPECT().GetByEmail(ctx, f.user.Email).Return(f.user, nil).Once()
		f.sender.EXPECT().Send(ctx, mock.Anything).Run(func(context.Context, email.Mail) { cancel() }).Return(context.Canceled).Once()
		worked, err := f.delivery.DeliverOne(ctx)
		require.True(t, worked)
		require.ErrorIs(t, err, context.Canceled)
		// No Delete/Retry expectation: the interrupted worker must preserve the lease.
	})
}
