-- +goose Up

CREATE TABLE identity.users (
    id                  UUID        PRIMARY KEY,
    email               TEXT        NOT NULL,
    email_verified_at   TIMESTAMPTZ,
    state               TEXT        NOT NULL,

    created_at          TIMESTAMPTZ NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX users_email_uidx
    ON identity.users (email);

-- +goose Down

DROP TABLE identity.users;
