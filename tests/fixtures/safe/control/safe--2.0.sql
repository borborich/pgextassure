CREATE SCHEMA IF NOT EXISTS pgextassure_safe;

CREATE TABLE pgextassure_safe.install_marker (
    installed_at timestamptz NOT NULL DEFAULT pg_catalog.current_timestamp
);
