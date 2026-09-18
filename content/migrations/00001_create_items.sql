-- +goose Up

CREATE TABLE content.items (
    id                  UUID        PRIMARY KEY,
    owner_id            UUID        NOT NULL,

    source_type         TEXT        NOT NULL,
    original_url        TEXT,
    normalized_url      TEXT,
    normalized_url_hash BYTEA,
    source_text         TEXT,

    display_title       TEXT,
    review_status       TEXT        NOT NULL,

    created_at          TIMESTAMPTZ NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL,
    last_captured_at    TIMESTAMPTZ NOT NULL,
    kept_at             TIMESTAMPTZ,
    later_at            TIMESTAMPTZ,

    CONSTRAINT items_source_type_chk
        CHECK (source_type IN ('url', 'text')),

    CONSTRAINT items_source_shape_chk
        CHECK (
            (
                source_type = 'url'
                AND original_url IS NOT NULL
                AND normalized_url IS NOT NULL
                AND normalized_url_hash IS NOT NULL
                AND source_text IS NULL
            )
            OR
            (
                source_type = 'text'
                AND original_url IS NULL
                AND normalized_url IS NULL
                AND normalized_url_hash IS NULL
                AND source_text IS NOT NULL
            )
        ),

    CONSTRAINT items_url_hash_size_chk
        CHECK (
            normalized_url_hash IS NULL
            OR octet_length(normalized_url_hash) = 32
        ),

    CONSTRAINT items_review_status_chk
        CHECK (review_status IN ('none', 'later', 'done')),

    CONSTRAINT items_later_at_shape_chk
        CHECK ((review_status = 'later') = (later_at IS NOT NULL))
);

CREATE UNIQUE INDEX items_owner_url_hash_uidx
    ON content.items (owner_id, normalized_url_hash)
    WHERE source_type = 'url';

CREATE INDEX items_recent_idx
    ON content.items (owner_id, last_captured_at DESC, id DESC);

CREATE INDEX items_library_idx
    ON content.items (owner_id, kept_at DESC, id DESC)
    WHERE kept_at IS NOT NULL;

CREATE INDEX items_later_idx
    ON content.items (owner_id, later_at DESC, id DESC)
    WHERE review_status = 'later';

-- +goose Down

DROP TABLE content.items;