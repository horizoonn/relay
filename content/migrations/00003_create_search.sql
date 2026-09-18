-- +goose Up

CREATE SCHEMA content_extensions;
REVOKE ALL ON SCHEMA content_extensions FROM PUBLIC;

CREATE EXTENSION pg_trgm WITH SCHEMA content_extensions;

CREATE INDEX items_display_title_trgm_idx
    ON content.items
    USING gin (
        pg_catalog.casefold(
            display_title COLLATE pg_catalog."pg_unicode_fast"
        ) content_extensions.gin_trgm_ops
    )
    WHERE display_title IS NOT NULL;

CREATE INDEX items_source_trgm_idx
    ON content.items
    USING gin (
        pg_catalog.casefold(
            (
                CASE source_type
                    WHEN 'url' THEN original_url
                    ELSE source_text
                END
            ) COLLATE pg_catalog."pg_unicode_fast"
        ) content_extensions.gin_trgm_ops
    );

CREATE INDEX items_display_title_prefix_idx
    ON content.items (
        owner_id,
        (pg_catalog.casefold(
            display_title COLLATE pg_catalog."pg_unicode_fast"
        )) pg_catalog.text_pattern_ops
    )
    WHERE display_title IS NOT NULL;

-- +goose Down

DROP INDEX content.items_display_title_prefix_idx;
DROP INDEX content.items_source_trgm_idx;
DROP INDEX content.items_display_title_trgm_idx;

DROP EXTENSION pg_trgm;
DROP SCHEMA content_extensions;