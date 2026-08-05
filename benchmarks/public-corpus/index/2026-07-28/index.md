# PgExtAssure Extension Assurance Index

This is a reproducible inventory of static-analysis coverage for pinned public PostgreSQL extension revisions. It is **not a security rating, certification, vulnerability report, or allowlist decision**.

Snapshot: 9 projects; 8 analyses completed; 1 not completed. Latest pinned source revision date: 2026-07-26.

Generated from PgExtAssure 0.1.0-alpha.1 with ruleset 2026-07-28.2.

| Project | Pinned revision | Analysis | Files | Capability profile | Controls |
| --- | --- | --- | ---: | --- | --- |
| [hypopg](https://github.com/HypoPG/hypopg) | `21d5461ad186` | completed | 25 | database.schema-relocation, database.superuser-install | default scan scope |
| [pg_cron](https://github.com/citusdata/pg_cron) | `16618e69cb38` | completed | 22 | database.superuser-install, process.background-worker | default scan scope |
| [pg_net](https://github.com/supabase/pg_net) | `a8299b11182e` | completed | 49 | database.public-execute, database.security-definer, database.superuser-install, network.client, network.client-server, process.background-worker | default scan scope |
| [pg_partman](https://github.com/pgpartman/pg_partman) | `0e22336185b4` | completed | 237 | database.extension-install, database.public-execute, database.security-definer, process.background-worker | default scan scope |
| [pg_tle](https://github.com/aws/pg_tle) | `92f908bc77f0` | completed | 45 | database.extension-install, database.extension-update, database.schema-relocation, database.superuser-install, filesystem.read-write, process.background-worker | default scan scope |
| [pgaudit](https://github.com/pgaudit/pgaudit) | `f4563a68c72b` | completed | 4 | database.public-execute, database.schema-relocation, database.superuser-install | default scan scope |
| [pgmq](https://github.com/pgmq/pgmq) | `fde87d8fb83f` | completed | 80 | database.extension-install | default scan scope |
| [pgvector](https://github.com/pgvector/pgvector) | `a6420355c5d1` | completed | 82 | database.extension-install, database.schema-relocation, database.superuser-install | default scan scope |
| [timescaledb](https://github.com/timescale/timescaledb) | `77d9d3281ce1` | not completed | — | none observed | default scan scope |

## Interpretation boundary

A completed row means the pinned source was processed successfully. It does not constitute a security review. Capability profiles describe observed functionality and must not be interpreted as vulnerabilities. Finding counts, severities, rule identifiers, evidence, paths, and source excerpts are intentionally excluded.

Input integrity:

- normalized summary: `sha256:5cf8fee0f53fc25cc977281e1834e8e98f2693f0bc355edfebc2c1e48dfa15f8`
- pinned manifest: `sha256:061dbb47a483592f009feae230249d3d0f3939205d80a4c1748a7dce1cef9cb3`
