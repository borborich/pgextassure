# Admission Gateway 1.0

The PgExtAssure Admission Gateway exposes the offline `pilot enforce` boundary
over a small HTTP API. It accepts one complete Pilot Package, recomputes the
Admission Event against externally supplied anchors, and persists request
uniqueness and idempotency in either a local SQLite ledger or a shared
PostgreSQL ledger.

It has no vendor credentials, package extraction, installation authority, or
extension execution. SQLite mode makes no outbound connection. PostgreSQL mode
connects only to the database named by the operator-supplied DSN.

## Start locally

```bash
mkdir -m 700 gateway-state

pgextassure gateway serve \
  --host 127.0.0.1 \
  --port 8080 \
  --ledger gateway-state/admissions.sqlite3 \
  --maximum-request-bytes 268435456 \
  --maximum-concurrent-requests 4 \
  --request-timeout-seconds 30
```

The gateway refuses a non-loopback bind unless `--allow-remote` is explicit.
That flag does not add TLS or authentication. A remote deployment must place
the gateway behind an organization-owned reverse proxy or service mesh that
enforces mTLS/authentication, request-size limits, and network policy.

The ledger is created with mode `0600`. Existing ledgers granting group or
other access, symlink ledgers, and symlinked ledger directories are rejected.

## Shared PostgreSQL ledger

Use PostgreSQL when two or more gateway processes must share one global
idempotency boundary. Install the explicit optional dependency:

```bash
python -m pip install 'pgextassure[postgres]'
```

Provision schema 1 with [`deploy/postgres-ledger.sql`](../deploy/postgres-ledger.sql)
under a migration/owner role. Alternatively, a controlled first boot can add
`--initialize-postgres-ledger`; do not retain DDL rights on the runtime role.
The runtime role needs only `SELECT` on `pgextassure_ledger_metadata` and
`SELECT, INSERT` on `pgextassure_admissions`.

Write the libpq connection string to a dedicated secret file. The DSN is never
accepted as a command-line value and is not logged:

```bash
install -m 600 /dev/null gateway-state/postgres.dsn
printf '%s\n' \
  'postgresql://pgextassure_runtime:REDACTED@db.internal/assurance?sslmode=verify-full' \
  > gateway-state/postgres.dsn

pgextassure gateway serve \
  --host 127.0.0.1 \
  --port 8080 \
  --postgres-dsn-file gateway-state/postgres.dsn
```

The DSN file and every directory in its path must be regular, non-symlinked,
and the file must grant no group or other access. Use a dedicated database,
least-privilege runtime role, server identity verification, encrypted
connections, encrypted backups, and PostgreSQL high availability appropriate
to the admission boundary.

For the rootless container, Compose and Kubernetes profiles, see
[Admission Gateway deployment](gateway-deployment.md).

## Endpoints

### `GET /healthz`

Reports process liveness.

### `GET /readyz`

Returns ready only when the selected ledger and schema version can be queried.

### `POST /v1/admissions`

The request body is the exact Pilot Package ZIP with media type:

```text
application/vnd.pgextassure.pilot+zip
```

Required headers:

| Header | Meaning |
| --- | --- |
| `Content-Length` | Exact bounded package byte length |
| `Idempotency-Key` | ASCII retry identity, maximum 128 bytes |
| `X-PgExtAssure-Package-SHA256` | Out-of-band complete package digest |
| `X-PgExtAssure-Key-SHA256` | Out-of-band corporate public-key fingerprint |
| `X-PgExtAssure-Trust-Policy-SHA256` | Out-of-band Trust Policy digest |
| `X-PgExtAssure-Request-ID` | Trusted change/deployment request ID |
| `X-PgExtAssure-Target` | Trusted admission target |
| `X-PgExtAssure-Evaluated-On` | Receipt evaluation date |
| `X-PgExtAssure-Verified-On` | Receipt-use date |

All metadata headers are ASCII, control-free, bounded, and single-occurrence.
Chunked transfer encoding is rejected. The body is streamed into a private
temporary file, hashed before verification, and deleted after the request.

Example:

```bash
curl --fail-with-body \
  -X POST http://127.0.0.1:8080/v1/admissions \
  -H 'Content-Type: application/vnd.pgextassure.pilot+zip' \
  -H 'Idempotency-Key: deploy-2026-0042-attempt-1' \
  -H 'X-PgExtAssure-Package-SHA256: sha256:PACKAGE_DIGEST' \
  -H 'X-PgExtAssure-Key-SHA256: sha256:KEY_DIGEST' \
  -H 'X-PgExtAssure-Trust-Policy-SHA256: sha256:POLICY_DIGEST' \
  -H 'X-PgExtAssure-Request-ID: CHG-2026-0042' \
  -H 'X-PgExtAssure-Target: postgresql-prod/extension-slot-01' \
  -H 'X-PgExtAssure-Evaluated-On: 2026-07-29' \
  -H 'X-PgExtAssure-Verified-On: 2026-07-29' \
  --data-binary @pgextassure-enterprise-pilot.zip
```

## Response semantics

| Status | Meaning |
| --- | --- |
| `200` | Recomputed Admission Event is active and `allow` |
| `400` | Request framing, headers, dates, or limits are invalid |
| `404` | Unknown endpoint |
| `409` | Authentic deny/inactive event, or replay/idempotency conflict |
| `422` | Package integrity, signature, Trust Policy, or context verification failed |
| `500` | Local ledger or server operation failed |
| `503` | Bounded concurrent request capacity is exhausted |

Successful and inactive admission responses are canonical Admission Event 1.0.
Errors use
[`gateway-error-1.0.schema.json`](../schemas/gateway-error-1.0.schema.json).
Every response sets `Cache-Control: no-store`.

## Replay and idempotency behavior

The ledger uniquely binds `(request ID, target)` and the idempotency key.

- Retrying the same key, request context, and package digest returns the exact
  stored event with `X-PgExtAssure-Replayed: true`.
- Reusing an idempotency key for different context or bytes is rejected.
- Reusing request ID and target under another idempotency key is rejected.
- Stored event bytes are authenticated by a retained SHA-256 before replay.
- Failed integrity/cryptographic requests do not reserve request context.

SQLite supports one gateway writer per ledger. PostgreSQL uses transaction
advisory locks plus database uniqueness constraints, so multiple gateway
instances connected to the same primary execute one admission operation and
return byte-identical replay results. Do not use asynchronous replicas as
writable ledgers. Cross-region deployments must preserve a single strongly
consistent write boundary.
