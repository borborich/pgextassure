#!/bin/sh
set -eu

state_dir="${PGEXTASSURE_STATE_DIR:-/var/lib/pgextassure/private}"
ledger="${PGEXTASSURE_LEDGER:-${state_dir}/admissions.sqlite3}"
postgres_dsn_file="${PGEXTASSURE_POSTGRES_DSN_FILE:-}"
host="${PGEXTASSURE_HOST:-0.0.0.0}"
port="${PGEXTASSURE_PORT:-8080}"
maximum_request_bytes="${PGEXTASSURE_MAXIMUM_REQUEST_BYTES:-268435456}"
maximum_concurrent_requests="${PGEXTASSURE_MAXIMUM_CONCURRENT_REQUESTS:-4}"
request_timeout_seconds="${PGEXTASSURE_REQUEST_TIMEOUT_SECONDS:-30}"
openssl="${PGEXTASSURE_OPENSSL:-/usr/bin/openssl}"

mkdir -p "${state_dir}"
chmod 0700 "${state_dir}"

set -- \
    --host "${host}" \
    --port "${port}" \
    --maximum-request-bytes "${maximum_request_bytes}" \
    --maximum-concurrent-requests "${maximum_concurrent_requests}" \
    --request-timeout-seconds "${request_timeout_seconds}" \
    --openssl "${openssl}" \
    --allow-remote \
    "$@"

if [ -n "${postgres_dsn_file}" ]; then
    set -- --postgres-dsn-file "${postgres_dsn_file}" "$@"
else
    set -- --ledger "${ledger}" "$@"
fi

exec pgextassure gateway serve "$@"
