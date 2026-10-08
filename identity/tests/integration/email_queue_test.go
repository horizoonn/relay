//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/platform/pkg/postgres"
	"github.com/horizoonn/relay/platform/pkg/security/accessjwt"

	"github.com/horizoonn/relay/identity/internal/domain"
	"github.com/horizoonn/relay/identity/internal/mailcipher"
	emailrepo "github.com/horizoonn/relay/identity/internal/repository/postgres/emailjob"
	sessionrepo "github.com/horizoonn/relay/identity/internal/repository/postgres/session"
	userrepo "github.com/horizoonn/relay/identity/internal/repository/postgres/user"
	"github.com/horizoonn/relay/identity/internal/usecase/auth"
	"github.com/horizoonn/relay/identity/internal/usecase/email"
)

type failedEmailQueue struct {
	*emailrepo.Repository
	id  uuid.UUID
	err error
}

func (q *failedEmailQueue) Create(ctx context.Context, job email.MailJob) error {
	q.id = job.ID
	if err := q.Repository.Create(ctx, job); err != nil {
		return err
	}
	return q.err
}

func TestRegistrationEmailRollback(t *testing.T) {
	pool, ctx := testPool(t)
	tx := postgres.NewTxManager(pool)
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := accessjwt.NewIssuer("email-test", private)
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("email queue transaction failed")
	queue := &failedEmailQueue{
		Repository: emailrepo.NewRepository(tx.Executor, time.Second),
		err:        failure,
	}
	cipher, err := mailcipher.New([]byte(uuid.NewV7().String()))
	if err != nil {
		t.Fatal(err)
	}
	requests, err := email.NewRequests(queue, cipher, unlimitedLimiter{})
	if err != nil {
		t.Fatal(err)
	}
	service, err := auth.NewService(
		t.Context(),
		userrepo.NewRepository(tx.Executor, time.Second),
		sessionrepo.NewRepository(tx.Executor, time.Second),
		tx,
		issuer,
		testPasswordHasher(t),
		unlimitedLimiter{},
		requests,
	)
	if err != nil {
		t.Fatal(err)
	}
	email := uuid.NewV7().String() + "@example.com"
	id, err := service.Register(ctx, email, "sufficiently long password")
	if !errors.Is(err, failure) || id != uuid.Nil() {
		t.Fatalf("id=%s error=%v", id, err)
	}
	var accounts, jobs int
	if err := pool.QueryRow(
		ctx,
		`SELECT (SELECT count(*) FROM identity.users WHERE email=$1),(SELECT count(*) FROM identity.email_jobs WHERE id=$2)`,
		email,
		queue.id,
	).Scan(
		&accounts,
		&jobs,
	); err != nil ||
		accounts != 0 ||
		jobs != 0 {
		t.Fatalf("accounts=%d jobs=%d err=%v", accounts, jobs, err)
	}
}

func TestEmailQueueClaimsAndLeaseOwnership(t *testing.T) {
	pool, ctx := testPool(t)
	tx := postgres.NewTxManager(pool)
	queue := emailrepo.NewRepository(tx.Executor, 5*time.Second)
	now := time.Now().UTC().Truncate(time.Microsecond)
	const count = 8
	ids := make(map[uuid.UUID]bool, count)
	for range count {
		job := email.MailJob{
			ID:               uuid.NewV7(),
			EncryptedPayload: make([]byte, 32),
			CreatedAt:        now,
			ExpiresAt:        now.Add(time.Hour),
		}
		ids[job.ID] = false
		if err := queue.Create(ctx, job); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, err := pool.Exec(context.WithoutCancel(ctx), `DELETE FROM identity.email_jobs WHERE id=$1`, job.ID)
			if err != nil {
				t.Error(err)
			}
		})
	}
	results := make(chan email.MailJob, count)
	failures := make(chan error, count)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range count {
		wg.Go(func() { <-start; job, err := queue.Claim(ctx, now); results <- job; failures <- err })
	}
	close(start)
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	var first email.MailJob
	for job := range results {
		seen, exists := ids[job.ID]
		if !exists || seen {
			t.Fatal("email job was claimed twice or belongs to another request")
		}
		ids[job.ID] = true
		first = job
	}
	if _, err := queue.Claim(ctx, now); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("leased email was claimed again")
	}

	if _, err := pool.Exec(ctx, `UPDATE identity.email_jobs SET lease_until=$2 WHERE id=$1`, first.ID, now); err != nil {
		t.Fatal(err)
	}
	replacement, err := queue.Claim(ctx, now)
	if err != nil || replacement.ID != first.ID || replacement.LeaseToken == first.LeaseToken {
		t.Fatal("lease was not replaced")
	}
	if err := queue.Delete(ctx, first); err != nil {
		t.Fatal(err)
	}
	var remaining bool
	if err := pool.QueryRow(
		ctx,
		`SELECT EXISTS(SELECT 1 FROM identity.email_jobs WHERE id=$1 AND lease_token=$2)`,
		replacement.ID,
		replacement.LeaseToken,
	).Scan(&remaining); err != nil ||
		!remaining {
		t.Fatal("stale worker deleted replacement lease")
	}
	if err := queue.Delete(ctx, replacement); err != nil {
		t.Fatal(err)
	}
}
