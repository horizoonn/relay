FROM golang:1.27.0-trixie AS goose-builder

ARG GOOSE_VERSION=v3.27.3
RUN CGO_ENABLED=0 GOBIN=/out \
    go install -tags='no_clickhouse no_libsql no_mssql no_azuresql no_mysql no_sqlite3 no_vertica no_ydb' \
    github.com/pressly/goose/v3/cmd/goose@${GOOSE_VERSION}

FROM debian:13-slim AS migrate

RUN groupadd --system app \
    && useradd --system --gid app --home-dir /app --create-home app

WORKDIR /app

COPY --from=goose-builder /out/goose /usr/local/bin/goose
COPY --chown=app:app identity/migrations /migrations
COPY --chown=app:app deploy/docker/run-migrations.sh /usr/local/bin/run-migrations

USER app

ENV GOOSE_MIGRATION_DIR=/migrations \
    GOOSE_TABLE=goose.goose_db_version
ENTRYPOINT ["/bin/sh", "/usr/local/bin/run-migrations"]

FROM golang:1.27.0-trixie AS app-builder

WORKDIR /src

COPY identity/go.* ./identity/
COPY platform/go.* ./platform/
COPY shared/go.* ./shared/
RUN cd identity && GOWORK=off go mod download

COPY identity ./identity
COPY platform ./platform
COPY shared ./shared

ARG TARGETOS=linux
ARG TARGETARCH
RUN cd identity \
    && GOWORK=off CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags='-s -w' -o /out/identity ./cmd/identity

FROM debian:13-slim AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system app \
    && useradd --system --gid app --home-dir /app --create-home app

WORKDIR /app

COPY --from=app-builder --chown=app:app /out/identity /app/identity

USER app
ENTRYPOINT ["/app/identity"]
