# Public corpus expansion — 2026-07-29

This follow-up expands the scanner-quality corpus from 9 to 16 pinned public
PostgreSQL extension repositories. It is not a security ranking and does not
claim that any matched condition is exploitable. Raw evidence remains private
behind the review and coordinated-disclosure gate.

## Reproducibility

- PgExtAssure source snapshot:
  `26adc7c5652fb71d2cb3e80587a2552de9b82aa3`
- release base: `0.1.0-alpha.5`
- ruleset: `2026-07-28.4`
- corpus: 16 repositories pinned to full Git commit identifiers in
  `manifest-alpha5.tsv`
- completed scans: 13 repositories, 827 supported source files
- fail-closed scans: 3 repositories
- raw rule matches in completed scans: 852
- conservative root causes: 277
- review-queue reduction: 67.5%
- normalized `summary.json` SHA-256:
  `041236c752cacb9adc68384a97ab746fb33a20479cd0a3ef10aad8e2bef2e381`
- normalized `summary.tsv` SHA-256:
  `a70f88b1f55236a6700c46245afcde4985e3278dad5d713f5abfe54b9d221f2f`

Runs under Python 3.11 and Python 3.14, plus a repeated Python 3.14 run,
produced byte-identical normalized JSON and TSV summaries.

| Severity | Findings | Root causes |
| --- | ---: | ---: |
| Critical | 384 | 101 |
| High | 453 | 161 |
| Medium | 9 | 9 |
| Low | 6 | 6 |
| **Total** | **852** | **277** |

| Repository | Scan path | Status | Files |
| --- | --- | --- | ---: |
| hypopg | `.` | completed | 25 |
| orafce | `.` | completed | 99 |
| pg_cron | `.` | completed | 22 |
| pg_duckdb | `.` | completed | 90 |
| pg_hint_plan | `.` | completed | 57 |
| pg_net | `.` | completed | 49 |
| pg_partman | `.` | completed | 237 |
| pg_repack | `lib` | completed | 6 |
| pg_stat_monitor | `.` | fail-closed: `resource_limit` | — |
| pg_tle | `.` | completed | 45 |
| pgaudit | `.` | completed | 4 |
| pgmq | `pgmq-extension` | completed | 80 |
| pgvector | `.` | completed | 82 |
| pgvectorscale | `pgvectorscale` | fail-closed: `symlinked_source` | — |
| timescaledb | `.` | fail-closed: `symlinked_directory` | — |
| wal2json | `.` | completed | 31 |

## Scanner-quality outcome

The expansion exposed four false high signals in named/default
`SECURITY DEFINER` argument declarations. PostgreSQL privilege statements
identify routines by argument types, while the scanner had retained declaration
names and defaults in its correlation key. The snapshot above normalizes
declarations to identity-argument syntax, preserves overload separation, and
has regression coverage for named/default and multiword argument types.

The fix reduced the affected repository from 12 to 8 high signals without
removing any other corpus result. The remaining new high records were reviewed
as explicit capability declarations, privileged-install requirements, or
unresolved records that remain behind the publication gate. No new raw
project-specific evidence is published here.

The three fail-closed results identify a separate product requirement:
enterprise users need an explicit, digest-bound way to define multiple package
roots and exclusions without following symlinks or silently skipping oversized
supported inputs. This result does not weaken or bypass the current safety
boundaries.

## Reproduce

Prepare detached checkouts using `manifest-alpha5.tsv`, then run:

```bash
python tools/run_public_corpus.py /path/to/corpus \
  --manifest benchmarks/public-corpus/manifest-alpha5.tsv \
  --output-dir /private/path/to/normalized-results
```

The runner is expected to exit `1` because all three fail-closed results are
part of this pinned benchmark. Do not use `--raw-report-dir` unless the output
will remain private and be manually adjudicated.
