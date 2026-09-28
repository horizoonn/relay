package model

import (
	"database/sql"
	"fmt"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/horizoonn/relay/content/internal/usecase/capture"
)

type Idempotency struct {
	FingerprintVersion int16
	Fingerprint        []byte
	ItemID             pgtype.UUID
	Outcome            sql.NullString
}

func (storedRecord *Idempotency) Scan(row pgx.Row) error {
	return row.Scan(&storedRecord.FingerprintVersion, &storedRecord.Fingerprint, &storedRecord.ItemID, &storedRecord.Outcome)
}

func (storedRecord Idempotency) ToRecord() (capture.IdempotencyRecord, error) {
	var record capture.IdempotencyRecord
	if len(storedRecord.Fingerprint) != len(record.Fingerprint) {
		return record, fmt.Errorf("invalid stored fingerprint size")
	}
	record.FingerprintVersion = storedRecord.FingerprintVersion
	copy(record.Fingerprint[:], storedRecord.Fingerprint)
	if storedRecord.ItemID.Valid {
		record.ItemID = uuid.UUID(storedRecord.ItemID.Bytes)
	}
	if storedRecord.Outcome.Valid {
		record.Outcome = capture.Outcome(storedRecord.Outcome.String)
	}
	return record, nil
}
