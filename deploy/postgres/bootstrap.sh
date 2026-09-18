#!/usr/bin/env bash
set -Eeuo pipefail

export PGHOST="${POSTGRES_HOST:-postgres}"
export PGPORT="${POSTGRES_PORT:-5432}"
export PGUSER="${POSTGRES_ADMIN_USER:?POSTGRES_ADMIN_USER is required}"
export PGPASSWORD="${POSTGRES_ADMIN_PASSWORD:?POSTGRES_ADMIN_PASSWORD is required}"

ensure_service_database() {
  local service="$1"
  local database_var="${service^^}_DB"
  local app_user_var="${service^^}_APP_USER"
  local app_password_var="${service^^}_APP_PASSWORD"
  local migrator_user_var="${service^^}_MIGRATOR_USER"
  local migrator_password_var="${service^^}_MIGRATOR_PASSWORD"
  local database="${!database_var:?${database_var} is required}"
  local app_user="${!app_user_var:?${app_user_var} is required}"
  local app_password="${!app_password_var:?${app_password_var} is required}"
  local migrator_user="${!migrator_user_var:?${migrator_user_var} is required}"
  local migrator_password="${!migrator_password_var:?${migrator_password_var} is required}"
  local service_schema="$service"

  psql --dbname=postgres --set=ON_ERROR_STOP=1 \
    --set=app_user="$app_user" \
    --set=app_password="$app_password" \
    --set=migrator_user="$migrator_user" \
    --set=migrator_password="$migrator_password" \
    --set=database="$database" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'app_user', :'app_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'app_user') \gexec
SELECT format('ALTER ROLE %I LOGIN PASSWORD %L', :'app_user', :'app_password') \gexec

SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'migrator_user', :'migrator_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'migrator_user') \gexec
SELECT format('ALTER ROLE %I LOGIN PASSWORD %L', :'migrator_user', :'migrator_password') \gexec

SELECT format('CREATE DATABASE %I OWNER %I', :'database', :'migrator_user')
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = :'database') \gexec
SELECT format('ALTER DATABASE %I OWNER TO %I', :'database', :'migrator_user') \gexec

REVOKE ALL ON DATABASE :"database" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"database" TO :"app_user", :"migrator_user";
SQL

  psql --dbname="$database" --set=ON_ERROR_STOP=1 \
    --set=app_user="$app_user" \
    --set=migrator_user="$migrator_user" \
    --set=database="$database" \
    --set=service_schema="$service_schema" <<'SQL'
REVOKE ALL ON SCHEMA public FROM PUBLIC;

SELECT format('CREATE SCHEMA IF NOT EXISTS %I AUTHORIZATION %I', :'service_schema', :'migrator_user') \gexec
SELECT format('ALTER SCHEMA %I OWNER TO %I', :'service_schema', :'migrator_user') \gexec
REVOKE ALL ON SCHEMA :"service_schema" FROM PUBLIC;
GRANT USAGE ON SCHEMA :"service_schema" TO :"app_user";

SELECT format('CREATE SCHEMA IF NOT EXISTS goose AUTHORIZATION %I', :'migrator_user') \gexec
ALTER SCHEMA goose OWNER TO :"migrator_user";
REVOKE ALL ON SCHEMA goose FROM PUBLIC;
REVOKE ALL ON SCHEMA goose FROM :"app_user";

GRANT SELECT, INSERT, UPDATE, DELETE
ON ALL TABLES IN SCHEMA :"service_schema"
TO :"app_user";
GRANT USAGE, SELECT
ON ALL SEQUENCES IN SCHEMA :"service_schema"
TO :"app_user";

ALTER DEFAULT PRIVILEGES
FOR ROLE :"migrator_user"
IN SCHEMA :"service_schema"
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO :"app_user";
ALTER DEFAULT PRIVILEGES
FOR ROLE :"migrator_user"
IN SCHEMA :"service_schema"
GRANT USAGE, SELECT ON SEQUENCES TO :"app_user";

SELECT format(
  'ALTER ROLE %I IN DATABASE %I SET search_path = pg_catalog, %I',
  :'app_user', :'database', :'service_schema'
) \gexec
SELECT format(
  'ALTER ROLE %I IN DATABASE %I SET search_path = pg_catalog, %I',
  :'migrator_user', :'database', :'service_schema'
) \gexec
SQL

  printf 'Database, roles, and schema are ready for %s\n' "$service"
}

for service in content delivery identity processing; do
  ensure_service_database "$service"
done