package email

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"time"
	"uuid"

	"github.com/horizoonn/relay/identity/internal/domain"
	identitylimit "github.com/horizoonn/relay/identity/internal/ratelimit"
	"github.com/horizoonn/relay/identity/internal/secret"
)

const passwordChangedMail = "password_changed"

type mailPayload struct {
	Email   string
	Purpose string
	Token   string
}

type Requests struct {
	queue   EmailQueue
	cipher  PayloadSealer
	limiter RateLimiter
}

func NewRequests(
	queue EmailQueue,
	cipher PayloadSealer,
	limiter RateLimiter,
) (*Requests, error) {
	if queue == nil || cipher == nil || limiter == nil {
		return nil, errors.New("email requests require queue, cipher and rate limiter")
	}
	return &Requests{
		queue:   queue,
		cipher:  cipher,
		limiter: limiter,
	}, nil
}

func (s *Requests) RequestVerification(ctx context.Context, email string) error {
	return s.request(ctx, email, domain.VerifyEmail, true)
}

func (s *Requests) RequestPasswordReset(ctx context.Context, email string) error {
	return s.request(ctx, email, domain.ResetPassword, true)
}

func (s *Requests) QueueVerification(ctx context.Context, email string) error {
	return s.request(ctx, email, domain.VerifyEmail, false)
}

func (s *Requests) request(
	ctx context.Context,
	email string,
	purpose domain.AccountTokenPurpose,
	limit bool,
) error {
	email, err := domain.NormalizeEmail(email)
	if err != nil {
		return err
	}
	if limit {
		if limitErr := s.limiter.Allow(ctx, identitylimit.EmailAccount, email); limitErr != nil {
			return fmt.Errorf("limit account email request: %w", limitErr)
		}
	}
	token, err := secret.Generate()
	if err != nil {
		return fmt.Errorf("generate account email token: %w", err)
	}
	return s.enqueue(ctx, mailPayload{
		Email:   email,
		Purpose: string(purpose),
		Token:   token,
	}, purpose.Lifetime())
}

func (s *Requests) QueuePasswordChanged(ctx context.Context, email string) error {
	email, err := domain.NormalizeEmail(email)
	if err != nil {
		return err
	}
	return s.enqueue(ctx, mailPayload{
		Email:   email,
		Purpose: passwordChangedMail,
	}, 24*time.Hour)
}

func (s *Requests) enqueue(
	ctx context.Context,
	payload mailPayload,
	lifetime time.Duration,
) error {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode email payload: %w", err)
	}
	encrypted, err := s.cipher.Seal(encoded)
	if err != nil {
		return fmt.Errorf("encrypt email payload: %w", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	job := MailJob{
		ID:               uuid.NewV7(),
		EncryptedPayload: encrypted,
		CreatedAt:        now,
		ExpiresAt:        now.Add(lifetime),
	}
	if queueErr := s.queue.Create(ctx, job); queueErr != nil {
		return fmt.Errorf("enqueue email job: %w", queueErr)
	}
	return nil
}
