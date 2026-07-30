BEGIN;

SELECT pg_advisory_xact_lock(5784668492053697363);

CREATE TABLE IF NOT EXISTS pgextassure_ledger_metadata (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    schema_version INTEGER NOT NULL
);

INSERT INTO pgextassure_ledger_metadata (singleton, schema_version)
VALUES (TRUE, 1)
ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS pgextassure_admissions (
    idempotency_key TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    target TEXT NOT NULL,
    package_digest TEXT NOT NULL,
    event_json BYTEA NOT NULL,
    event_sha256 TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (request_id, target)
);

COMMIT;
