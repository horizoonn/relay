-- +goose Up

CREATE TABLE identity.password_credentials (
    user_id             UUID        PRIMARY KEY,
    password_hash       TEXT        NOT NULL,

    created_at          TIMESTAMPTZ NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL,

    CONSTRAINT password_credentials_user_id_fkey
        FOREIGN KEY (user_id)
        REFERENCES identity.users (id)
        ON DELETE CASCADE
);

-- +goose Down

DROP TABLE identity.password_credentials;
