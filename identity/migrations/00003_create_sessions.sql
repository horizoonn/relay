-- +goose Up

CREATE TABLE identity.sessions (
    id                  UUID        PRIMARY KEY,
    user_id             UUID        NOT NULL,
    csrf_hash           BYTEA       NOT NULL,

    created_at          TIMESTAMPTZ NOT NULL,
    authenticated_at    TIMESTAMPTZ NOT NULL,
    last_seen_at        TIMESTAMPTZ NOT NULL,
    expires_at          TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ,

    CONSTRAINT sessions_user_id_fkey
        FOREIGN KEY (user_id)
        REFERENCES identity.users (id)
        ON DELETE CASCADE,

    CONSTRAINT sessions_csrf_hash_size_chk
        CHECK (octet_length(csrf_hash) = 32)
);

CREATE INDEX sessions_user_created_at_idx
    ON identity.sessions (user_id, created_at DESC, id DESC);

CREATE INDEX sessions_expires_at_idx
    ON identity.sessions (expires_at);

-- +goose Down

DROP TABLE identity.sessions;
