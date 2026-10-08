package email

import (
	"context"
	"encoding/json/v2"
	"errors"
	"testing"

	"github.com/horizoonn/relay/identity/internal/domain"
	"github.com/horizoonn/relay/identity/internal/mailcipher"
	identitylimit "github.com/horizoonn/relay/identity/internal/ratelimit"
	"github.com/horizoonn/relay/identity/internal/secret"
)

type requestQueue struct {
	jobs []MailJob
	err  error
}

func (q *requestQueue) Create(_ context.Context, job MailJob) error {
	if q.err != nil {
		return q.err
	}
	q.jobs = append(q.jobs, job)
	return nil
}

type requestLimiter struct {
	subject string
	err     error
}

func (l *requestLimiter) Allow(
	_ context.Context,
	scope identitylimit.Scope,
	subject string,
) error {
	if scope != identitylimit.EmailAccount {
		return errors.New("incorrect scope")
	}
	l.subject = subject
	return l.err
}

func TestRequestsQueueEncryptedPayload(t *testing.T) {
	cipher, err := mailcipher.New([]byte("unit-mail-encryption-key-at-least-32-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name         string
		purpose      domain.AccountTokenPurpose
		registration bool
	}{
		{
			name:         "verification resend",
			purpose:      domain.VerifyEmail,
			registration: false,
		}, {
			name:         "password recovery",
			purpose:      domain.ResetPassword,
			registration: false,
		}, {
			name:         "registration confirmation",
			purpose:      domain.VerifyEmail,
			registration: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			queue, limiter := &requestQueue{}, &requestLimiter{}
			requests, err := NewRequests(queue, cipher, limiter)
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case tc.registration:
				err = requests.QueueVerification(t.Context(), "  Account@EXAMPLE.COM  ")
			case tc.purpose == domain.VerifyEmail:
				err = requests.RequestVerification(t.Context(), "  Account@EXAMPLE.COM  ")
			default:
				err = requests.RequestPasswordReset(t.Context(), "  Account@EXAMPLE.COM  ")
			}
			if err != nil || len(queue.jobs) != 1 {
				t.Fatalf("jobs=%d err=%v", len(queue.jobs), err)
			}
			if !tc.registration && limiter.subject != "Account@example.com" {
				t.Fatal("budget did not use normalized identity")
			}
			if tc.registration && limiter.subject != "" {
				t.Fatal("registration charged resend budget")
			}
			job := queue.jobs[0]
			plain, err := cipher.Open(job.EncryptedPayload)
			if err != nil {
				t.Fatal(err)
			}
			var payload mailPayload
			if err := json.Unmarshal(plain, &payload); err != nil {
				t.Fatal(err)
			}
			if payload.Email != "Account@example.com" ||
				payload.Purpose != string(tc.purpose) ||
				job.ExpiresAt.Sub(job.CreatedAt) != tc.purpose.Lifetime() {
				t.Fatal("incorrect account request")
			}
			if _, err := secret.Digest(payload.Token); err != nil {
				t.Fatal("invalid credential")
			}
		})
	}
	failure := errors.New("rate limited")
	for _, tc := range []struct {
		name      string
		email     string
		budgetErr error
		queueErr  error
		want      error
	}{
		{
			name:  "invalid email",
			email: "invalid",
			want:  domain.ErrInvalidEmail,
		},
		{
			name:      "rate limited",
			email:     "account@example.com",
			budgetErr: failure,
			want:      failure,
		},
		{
			name:     "queue failure",
			email:    "account@example.com",
			queueErr: failure,
			want:     failure,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			queue := &requestQueue{
				err: tc.queueErr,
			}
			requests, err := NewRequests(queue, cipher, &requestLimiter{
				err: tc.budgetErr,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := requests.RequestPasswordReset(t.Context(), tc.email); !errors.Is(err, tc.want) {
				t.Fatalf("error=%v", err)
			}
			if len(queue.jobs) != 0 {
				t.Fatal("rejected request created a job")
			}
		})
	}
}
