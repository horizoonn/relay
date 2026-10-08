#!/bin/sh
set -eu

migration_dir="${GOOSE_MIGRATION_DIR:-/migrations}"

if ! find "$migration_dir" -maxdepth 1 -type f -name '*.sql' -print -quit | grep -q .; then
  printf 'No SQL migrations found in %s; nothing to apply.\n' "$migration_dir"
  exit 0
fi

: "${GOOSE_DBSTRING:?GOOSE_DBSTRING is required}"
export GOOSE_DRIVER=postgres
exec goose -dir "$migration_dir" up
