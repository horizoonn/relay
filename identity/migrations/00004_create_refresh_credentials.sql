-- +goose Up

CREATE TABLE identity.refresh_credentials (
    token_hash          BYTEA       PRIMARY KEY,
    session_id          UUID        NOT NULL,
    generation          BIGINT      NOT NULL,

    created_at          TIMESTAMPTZ NOT NULL,
    expires_at          TIMESTAMPTZ NOT NULL,
    used_at             TIMESTAMPTZ,

    CONSTRAINT refresh_credentials_session_id_fkey
        FOREIGN KEY (session_id)
        REFERENCES identity.sessions (id)
        ON DELETE CASCADE,

    CONSTRAINT refresh_credentials_token_hash_size_chk
        CHECK (octet_length(token_hash) = 32)
);

CREATE UNIQUE INDEX refresh_credentials_session_generation_uidx
    ON identity.refresh_credentials (session_id, generation);

CREATE UNIQUE INDEX refresh_credentials_current_session_uidx
    ON identity.refresh_credentials (session_id)
    WHERE used_at IS NULL;

CREATE INDEX refresh_credentials_expires_at_idx
    ON identity.refresh_credentials (expires_at);

-- +goose Down

DROP TABLE identity.refresh_credentials;
