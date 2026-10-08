-- +goose Up

CREATE TABLE identity.account_tokens (
    token_hash BYTEA       PRIMARY KEY,
    user_id    UUID        NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
    purpose    TEXT        NOT NULL,

    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,

    CONSTRAINT account_tokens_hash_size_chk
        CHECK (octet_length(token_hash) = 32),

    CONSTRAINT account_tokens_purpose_chk
        CHECK (purpose IN ('verify_email', 'reset_password')),

    CONSTRAINT account_tokens_expiry_chk
        CHECK (expires_at > created_at),

    CONSTRAINT account_tokens_used_at_chk
        CHECK (used_at >= created_at)
);

CREATE INDEX account_tokens_expiry_idx
    ON identity.account_tokens (expires_at);

CREATE INDEX account_tokens_user_purpose_idx
    ON identity.account_tokens (user_id, purpose)
    WHERE used_at IS NULL;

-- Encrypted requests are queued even for unknown email addresses. HTTP does not
-- wait for account lookup or SMTP. The worker silently discards ineligible jobs.
CREATE TABLE identity.email_jobs (
    id                UUID        PRIMARY KEY,
    encrypted_payload BYTEA       NOT NULL,
    prepared_user_id  UUID        REFERENCES identity.users(id) ON DELETE CASCADE,
    created_at        TIMESTAMPTZ NOT NULL,
    expires_at        TIMESTAMPTZ NOT NULL,
    available_at      TIMESTAMPTZ NOT NULL,
    lease_token       UUID,
    lease_until       TIMESTAMPTZ,
    attempts          INTEGER     NOT NULL DEFAULT 0,

    CONSTRAINT email_jobs_payload_size_chk
        CHECK (octet_length(encrypted_payload) BETWEEN 29 AND 2048),

    CONSTRAINT email_jobs_expiry_chk
        CHECK (expires_at > created_at),

    CONSTRAINT email_jobs_attempts_chk
        CHECK (attempts >= 0),

    CONSTRAINT email_jobs_lease_shape_chk
        CHECK ((lease_token IS NULL) = (lease_until IS NULL))
);

CREATE INDEX email_jobs_available_idx
    ON identity.email_jobs (available_at, id);

-- +goose Down

DROP TABLE identity.email_jobs;
DROP TABLE identity.account_tokens;
