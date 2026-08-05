# PgExtAssure Extension Assurance Index

This is a reproducible inventory of static-analysis coverage for pinned public PostgreSQL extension revisions. It is **not a security rating, certification, vulnerability report, or allowlist decision**.

Snapshot: 16 projects; 16 analyses completed; 0 not completed. Latest pinned source revision date: 2026-07-26.

Generated from PgExtAssure 0.1.0-alpha.15 with ruleset 2026-07-29.6.

| Project | Pinned revision | Analysis | Files | Capability profile | Controls |
| --- | --- | --- | ---: | --- | --- |
| [hypopg](https://github.com/HypoPG/hypopg) | `21d5461ad186` | completed | 25 | database.schema-relocation, database.superuser-install | default scan scope |
| [orafce](https://github.com/orafce/orafce) | `ca0a3d3e4a2f` | completed | 99 | database.public-execute, database.superuser-install, filesystem.read-write | default scan scope |
| [pg_cron](https://github.com/citusdata/pg_cron) | `16618e69cb38` | completed | 22 | database.superuser-install, process.background-worker | default scan scope |
| [pg_duckdb](https://github.com/duckdb/pg_duckdb) | `ee38d3b540ec` | completed | 90 | database.public-execute, database.superuser-install | default scan scope |
| [pg_hint_plan](https://github.com/ossc-db/pg_hint_plan) | `53889a76b13f` | completed | 57 | database.superuser-install | default scan scope |
| [pg_net](https://github.com/supabase/pg_net) | `a8299b11182e` | completed | 49 | database.public-execute, database.security-definer, database.superuser-install, network.client, network.client-server, process.background-worker | default scan scope |
| [pg_partman](https://github.com/pgpartman/pg_partman) | `0e22336185b4` | completed | 237 | database.public-execute, database.security-definer, process.background-worker | generation plan |
| [pg_repack](https://github.com/reorg/pg_repack) | `82120316e840` | completed | 6 | database.public-execute, database.superuser-install | default scan scope |
| [pg_stat_monitor](https://github.com/percona/pg_stat_monitor) | `61c954b6b8ac` | completed | 37 | database.public-execute, database.schema-relocation, database.superuser-install | scope plan |
| [pg_tle](https://github.com/aws/pg_tle) | `92f908bc77f0` | completed | 45 | database.schema-relocation, database.superuser-install, filesystem.read-write, process.background-worker | generation plan |
| [pgaudit](https://github.com/pgaudit/pgaudit) | `f4563a68c72b` | completed | 4 | database.public-execute, database.schema-relocation, database.superuser-install | default scan scope |
| [pgmq](https://github.com/pgmq/pgmq) | `fde87d8fb83f` | completed | 80 | none observed | generation plan |
| [pgvector](https://github.com/pgvector/pgvector) | `a6420355c5d1` | completed | 82 | database.schema-relocation, database.superuser-install | generation plan |
| [pgvectorscale](https://github.com/timescale/pgvectorscale) | `57c88b7b4fe4` | completed | 62 | database.extension-install, database.extension-update, database.superuser-install, filesystem.read-write, memory.unsafe, process.execute | scope plan |
| [timescaledb](https://github.com/timescale/timescaledb) | `77d9d3281ce1` | completed | 1188 | database.extension-install, database.extension-update, database.superuser-install, database.trusted-install, filesystem.read-write, network.client-server, process.background-worker | scope plan |
| [wal2json](https://github.com/eulerto/wal2json) | `79d516e60463` | completed | 31 | none observed | default scan scope |

## Interpretation boundary

A completed row means the pinned source was processed successfully. It does not constitute a security review. Capability profiles describe observed functionality and must not be interpreted as vulnerabilities. Finding counts, severities, rule identifiers, evidence, paths, and source excerpts are intentionally excluded.

Input integrity:

- normalized summary: `sha256:7f88c82de6b643b2e3c316a7c12b1dbe6c2fd2ce56e0d8308e3797060ce40b07`
- pinned manifest: `sha256:a088517818917cd137d9ccf671ef42a1410d8656337de5668ea95469e0510404`
