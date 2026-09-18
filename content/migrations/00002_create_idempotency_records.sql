-- +goose Up

CREATE TABLE content.idempotency_records (
    owner_id            UUID        NOT NULL,
    operation           TEXT        NOT NULL,
    idempotency_key     TEXT        NOT NULL,
    request_fingerprint BYTEA       NOT NULL,

    item_id             UUID,
    outcome             TEXT,

    created_at          TIMESTAMPTZ NOT NULL,

    CONSTRAINT idempotency_records_pkey
        PRIMARY KEY (owner_id, operation, idempotency_key),

    CONSTRAINT idempotency_records_fingerprint_size_chk
        CHECK (octet_length(request_fingerprint) = 32),

    CONSTRAINT idempotency_records_outcome_chk
        CHECK (
            outcome IS NULL
            OR outcome IN ('created', 'reused')
        ),

    CONSTRAINT idempotency_records_result_shape_chk
        CHECK (
            (item_id IS NULL) = (outcome IS NULL)
        )
);

CREATE INDEX idempotency_records_created_at_idx
    ON content.idempotency_records (created_at);

-- +goose Down

DROP TABLE content.idempotency_records;