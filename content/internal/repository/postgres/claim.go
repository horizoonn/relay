package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/horizoonn/relay/content/internal/repository/postgres/model"
	"github.com/horizoonn/relay/content/internal/usecase/capture"
)

func (r *Repository) Claim(
	ctx context.Context,
	params capture.ClaimParams,
) (capture.IdempotencyRecord, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	defer cancel()

	const query = `
		INSERT INTO content.idempotency_records (
			owner_id, operation, idempotency_key, fingerprint_version,
			request_fingerprint, created_at, expires_at
		) VALUES ($1, 'capture', $2, $3, $4, $5::timestamptz, $5::timestamptz + INTERVAL '7 days')
		ON CONFLICT (owner_id, operation, idempotency_key) DO UPDATE
		SET fingerprint_version = EXCLUDED.fingerprint_version,
			request_fingerprint = EXCLUDED.request_fingerprint,
			item_id = NULL,
			outcome = NULL,
			created_at = EXCLUDED.created_at,
			expires_at = EXCLUDED.expires_at
		WHERE content.idempotency_records.expires_at <= EXCLUDED.created_at
		RETURNING idempotency_key
	`

	row := r.executor(ctx).QueryRow(ctx,
		query,
		params.OwnerID,
		params.Key,
		params.FingerprintVersion,
		params.Fingerprint[:],
		params.Now,
	)
	var key string
	err := row.Scan(&key)
	if err == nil {
		return capture.IdempotencyRecord{}, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return capture.IdempotencyRecord{}, false, fmt.Errorf("claim capture receipt: %w", err)
	}
	const findQuery = `
		SELECT fingerprint_version, request_fingerprint, item_id, outcome
		FROM content.idempotency_records
		WHERE owner_id = $1 AND operation = 'capture' AND idempotency_key = $2
		FOR UPDATE
	`

	row = r.executor(ctx).QueryRow(ctx, findQuery, params.OwnerID, params.Key)
	var storedRecord model.Idempotency
	if scanErr := storedRecord.Scan(row); scanErr != nil {
		return capture.IdempotencyRecord{}, false, fmt.Errorf("load capture receipt: %w", scanErr)
	}
	record, err := storedRecord.ToRecord()
	if err != nil {
		return capture.IdempotencyRecord{}, false, fmt.Errorf("restore capture receipt: %w", err)
	}
	return record, false, nil
}
