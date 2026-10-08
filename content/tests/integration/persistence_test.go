//go:build integration

package integration

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/horizoonn/relay/platform/pkg/postgres"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/horizoonn/relay/content/internal/domain"
	contentrepo "github.com/horizoonn/relay/content/internal/repository/postgres"
	"github.com/horizoonn/relay/content/internal/usecase/capture"
	"github.com/horizoonn/relay/content/internal/usecase/search"
)

func TestItemConstraints(t *testing.T) {
	pool, ctx := testPool(t)
	owner := uuid.New()
	cleanupOwner(t, pool, owner)
	now := time.Now().UTC()
	base := `INSERT INTO content.items
		(id, owner_id, source_type, original_url, normalized_url, normalized_url_hash,
		 source_text, review_status, created_at, updated_at, last_captured_at, later_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$9,$10)`
	for _, tc := range []struct {
		name          string
		sourceType    string
		originalURL   string
		normalizedURL string
		sourceText    string
		reviewStatus  string
		constraint    string
		hash          []byte
		laterAt       any
	}{
		{
			name:          "url with text",
			sourceType:    "url",
			originalURL:   "https://example.com",
			normalizedURL: "https://example.com",
			sourceText:    "extra",
			reviewStatus:  "none",
			constraint:    "items_source_shape_chk",
			hash:          make([]byte, 32),
		},
		{
			name:          "short URL hash",
			sourceType:    "url",
			originalURL:   "https://example.com",
			normalizedURL: "https://example.com",
			reviewStatus:  "none",
			constraint:    "items_url_hash_size_chk",
			hash:          []byte{1},
		},
		{
			name:         "unknown review status",
			sourceType:   "text",
			sourceText:   "hello",
			reviewStatus: "ready",
			constraint:   "items_review_status_chk",
		},
		{
			name:         "later without timestamp",
			sourceType:   "text",
			sourceText:   "hello",
			reviewStatus: "later",
			constraint:   "items_later_at_shape_chk",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var originalURL, normalizedURL, sourceText any
			if tc.originalURL != "" {
				originalURL = tc.originalURL
			}
			if tc.normalizedURL != "" {
				normalizedURL = tc.normalizedURL
			}
			if tc.sourceText != "" {
				sourceText = tc.sourceText
			}
			_, err := pool.Exec(ctx, base, uuid.New(), owner, tc.sourceType, originalURL,
				normalizedURL, tc.hash, sourceText, tc.reviewStatus, now, tc.laterAt)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != tc.constraint {
				t.Fatalf("constraint = %v; want %s", err, tc.constraint)
			}
		})
	}
}

func TestURLUniquePerOwner(t *testing.T) {
	pool, ctx := testPool(t)
	owner, other := uuid.New(), uuid.New()
	cleanupOwner(t, pool, owner)
	cleanupOwner(t, pool, other)
	tx := postgres.NewTxManager(pool)
	repo := contentrepo.NewRepository(tx.Executor, 5*time.Second)
	source, err := domain.NewURLSource("https://example.com/" + uuid.New().String())
	if err != nil {
		t.Fatal(err)
	}
	create := func(owner uuid.UUID) bool {
		t.Helper()
		value, err := domain.NewItem(uuid.New(), owner, source, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		created, err := repo.Create(ctx, value)
		if err != nil {
			t.Fatal(err)
		}
		return created
	}
	if !create(owner) || create(owner) || !create(other) {
		t.Fatal("URL uniqueness must be scoped by owner")
	}
	var count int
	const urlCountQuery = `
		SELECT count(*)
		FROM content.items
		WHERE normalized_url = $1
	`
	if err := pool.QueryRow(ctx, urlCountQuery, source.NormalizedURL).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("URL rows = %d; want one for each owner", count)
	}
}

func TestReceiptConstraints(t *testing.T) {
	pool, ctx := testPool(t)
	owner := uuid.New()
	cleanupOwner(t, pool, owner)
	const insert = `
		INSERT INTO content.idempotency_records (
			owner_id, operation, idempotency_key, fingerprint_version,
			request_fingerprint, created_at, expires_at, item_id, outcome
		) VALUES ($1, 'capture', $2, $3, $4, $5::timestamptz, $5::timestamptz + INTERVAL '7 days', $6, $7)
	`
	for _, tc := range []struct {
		name        string
		constraint  string
		version     int16
		fingerprint []byte
		itemID      any
		outcome     any
	}{
		{
			name:        "short fingerprint",
			constraint:  "idempotency_records_fingerprint_size_chk",
			version:     1,
			fingerprint: []byte{1},
		},
		{
			name:        "zero version",
			constraint:  "idempotency_records_fingerprint_version_chk",
			fingerprint: make([]byte, 32),
		},
		{
			name:        "incomplete result",
			constraint:  "idempotency_records_result_shape_chk",
			version:     1,
			fingerprint: make([]byte, 32),
			itemID:      uuid.New(),
		},
		{
			name:        "invalid outcome",
			constraint:  "idempotency_records_outcome_chk",
			version:     1,
			fingerprint: make([]byte, 32),
			itemID:      uuid.New(),
			outcome:     "unknown",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := pool.Exec(ctx, insert, owner, uuid.New().String(), tc.version, tc.fingerprint,
				time.Now().UTC(), tc.itemID, tc.outcome)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != tc.constraint {
				t.Fatalf("constraint = %v; want %s", err, tc.constraint)
			}
		})
	}
}

func TestCaptureRollback(t *testing.T) {
	pool, ctx := testPool(t)
	owner := uuid.New()
	cleanupOwner(t, pool, owner)
	tx := postgres.NewTxManager(pool)
	repo := contentrepo.NewRepository(tx.Executor, 5*time.Second)
	command := capture.Command{
		OwnerID:        owner,
		IdempotencyKey: "same-key",
		SourceType:     domain.SourceText,
		Text:           "atomic capture",
	}
	rollback := errors.New("rollback")
	err := tx.WithinTransaction(ctx, func(ctx context.Context) error {
		_, claimed, err := repo.Claim(ctx, capture.ClaimParams{
			OwnerID:            owner,
			Key:                command.IdempotencyKey,
			FingerprintVersion: 1,
			Now:                time.Now().UTC(),
		})
		if err != nil {
			return err
		}
		if !claimed {
			return errors.New("receipt was not claimed")
		}
		source, err := domain.NewTextSource(command.Text)
		if err != nil {
			return err
		}
		value, err := domain.NewItem(uuid.New(), owner, source, time.Now().UTC())
		if err != nil {
			return err
		}
		if _, err := repo.Create(ctx, value); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatalf("transaction error = %v", err)
	}
	var items, receipts int
	const itemCountQuery = `
		SELECT count(*)
		FROM content.items
		WHERE owner_id = $1
	`
	const receiptCountQuery = `
		SELECT count(*)
		FROM content.idempotency_records
		WHERE owner_id = $1
	`
	if err := pool.QueryRow(ctx, itemCountQuery, owner).Scan(&items); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, receiptCountQuery, owner).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if items != 0 || receipts != 0 {
		t.Fatalf("rollback left %d items and %d receipts", items, receipts)
	}
}

func TestConcurrentSameKeyCapture(t *testing.T) {
	pool, ctx := testPool(t)
	owner := uuid.New()
	cleanupOwner(t, pool, owner)
	tx := postgres.NewTxManager(pool)
	repo := contentrepo.NewRepository(tx.Executor, 5*time.Second)
	svc := capture.NewService(repo, repo, tx)
	command := capture.Command{
		OwnerID:        owner,
		IdempotencyKey: "same-key",
		SourceType:     domain.SourceText,
		Text:           "atomic capture",
	}
	reached, release := make(chan int32, 1), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	held := holdBeforeCommit{TxManager: tx, reached: reached, release: release}
	firstService := capture.NewService(repo, repo, held)
	type captureResult struct {
		value capture.Result
		err   error
	}
	firstDone, secondDone := make(chan captureResult, 1), make(chan captureResult, 1)
	go func() { result, err := firstService.Capture(ctx, command); firstDone <- captureResult{result, err} }()
	pid := awaitHeldTransaction(t, ctx, reached)
	go func() { result, err := svc.Capture(ctx, command); secondDone <- captureResult{result, err} }()
	waitForLockWait(t, ctx, pool, pid)
	unblock()
	a, b := <-firstDone, <-secondDone
	results := []capture.Result{a.value, b.value}
	errs := []error{a.err, b.err}
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if results[0] != results[1] || results[0].Outcome != capture.OutcomeCreated {
		t.Fatalf("same-key captures = %+v", results)
	}
	var items, receipts int
	const itemCountQuery = `
		SELECT count(*)
		FROM content.items
		WHERE owner_id = $1
	`
	const receiptCountQuery = `
		SELECT count(*)
		FROM content.idempotency_records
		WHERE owner_id = $1
	`
	if err := pool.QueryRow(ctx, itemCountQuery, owner).Scan(&items); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, receiptCountQuery, owner).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if items != 1 || receipts != 1 {
		t.Fatalf("same-key capture left %d items and %d receipts", items, receipts)
	}
	var beforeCaptured time.Time
	const capturedAtQuery = `
		SELECT last_captured_at
		FROM content.items
		WHERE id = $1
	`
	if err := pool.QueryRow(ctx, capturedAtQuery, results[0].ItemID).Scan(&beforeCaptured); err != nil {
		t.Fatal(err)
	}
	changed := command
	changed.Text = "different"
	if _, err := svc.Capture(ctx, changed); !errors.Is(err, capture.ErrIdempotencyKeyReused) {
		t.Fatalf("same key with different body: %v", err)
	}
	var afterCaptured time.Time
	if err := pool.QueryRow(ctx, capturedAtQuery, results[0].ItemID).Scan(&afterCaptured); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, itemCountQuery, owner).Scan(&items); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, receiptCountQuery, owner).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if items != 1 || receipts != 1 || !afterCaptured.Equal(beforeCaptured) {
		t.Fatalf("key conflict changed state: items=%d receipts=%d captured=%s -> %s",
			items, receipts, beforeCaptured, afterCaptured)
	}
}

func TestSearchCasefoldOwnerScope(t *testing.T) {
	pool, ctx := testPool(t)
	owner, other := uuid.New(), uuid.New()
	cleanupOwner(t, pool, owner)
	cleanupOwner(t, pool, other)
	tx := postgres.NewTxManager(pool)
	repo := contentrepo.NewRepository(tx.Executor, 5*time.Second)
	create := func(owner uuid.UUID, title, body string) uuid.UUID {
		t.Helper()
		source, err := domain.NewTextSource(body)
		if err != nil {
			t.Fatal(err)
		}
		value, err := domain.NewItem(uuid.New(), owner, source, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		if title != "" {
			if titleErr := value.SetDisplayTitle(title, time.Now().UTC()); titleErr != nil {
				t.Fatal(titleErr)
			}
		}
		created, err := repo.Create(ctx, value)
		if err != nil || !created {
			t.Fatalf("create: %t, %v", created, err)
		}
		return value.ID()
	}
	want := create(owner, "Straße Guide", "content")
	create(owner, "Other", "great resource")
	create(other, "Straße Guide", "private")
	page, err := repo.Search(ctx, search.Params{
		OwnerID: owner,
		Query:   "strasse",
		Limit:   20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != want {
		t.Fatalf("casefold search = %+v", page.Items)
	}
	page, err = repo.Search(ctx, search.Params{
		OwnerID: owner,
		Query:   "gr",
		Limit:   20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 0 {
		t.Fatalf("short query matched body: %+v", page.Items)
	}
}
