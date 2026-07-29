# Admission Gateway 1.0

The PgExtAssure Admission Gateway exposes the offline `pilot enforce` boundary
over a small HTTP API. It accepts one complete Pilot Package, recomputes the
Admission Event against externally supplied anchors, and persists request
uniqueness and idempotency in a local SQLite ledger.

It has no outbound network client, vendor credentials, package extraction,
installation authority, or extension execution.

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

For the rootless container, Compose and Kubernetes profiles, see
[Admission Gateway deployment](gateway-deployment.md).

## Endpoints

### `GET /healthz`

Reports process liveness.

### `GET /readyz`

Returns ready only when the SQLite ledger can be queried.

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

The ledger is an operational control, not a distributed consensus system.
Run one writer per ledger. Multi-region deployments require an
organization-owned globally consistent request-uniqueness service.
