# Public corpus generation plans — 2026-07-28

This follow-up measures source-tree graph precision, not vulnerability count or
exploitability. It uses the same nine pinned revisions as the initial public
corpus pilot and publishes no raw evidence.

## Reproducibility

- PgExtAssure: `0.1.0-alpha.1`
- ruleset: `2026-07-28.4`
- generation-plan schema: `1.0`
- completed scans: 8 repositories, 544 supported source files
- fail-closed scans: 1 repository
- reviewed generation plans: 4
- declared or rendered virtual artifacts: 4
- findings before plans: 838
- findings after plans: 822
- root causes before plans: 263
- root causes after plans: 247
- normalized `summary.json` SHA-256:
  `b5201fe07698fb05f20dc766eafc4a217e27607914b15c82ecedab60922fab36`
- normalized `summary.tsv` SHA-256:
  `bc0ff982605566ad311354fcf788ea94ccdf4732e9afa3fc8cc454a0ee5c2d25`

Separate runs under Python 3.11.11 and Python 3.14.6 produced byte-identical
normalized JSON and TSV summaries.

The run used `manifest-generation.tsv`; generation plans are not applied by the
default corpus manifest.

| Severity | Before | After | Removed graph signals |
| --- | ---: | ---: | ---: |
| Critical | 384 | 384 | 0 |
| High | 439 | 427 | 12 |
| Medium | 9 | 5 | 4 |
| Low | 6 | 6 | 0 |
| **Total** | **838** | **822** | **16** |

The root-cause severity totals changed from 101/147/9/6 to 101/135/5/6 for
critical/high/medium/low respectively.

## What changed

One rendered control template resolved its pinned default version and removed
12 false missing-update-path records plus one false missing-install record.
Three declared generated install SQL paths removed three additional
missing-install records.

No critical, capability-inventory, native-code, or SQL-privilege finding was
suppressed. The plans affected only update-graph interpretation, except that
the rendered control was assessed at its generated path instead of
double-counting its source template.

Each plan pins the exact Makefile, control, SQL source, or template inputs used
for the declaration. A digest change fails the scan rather than silently
applying stale generation metadata. PgExtAssure did not run Make, shell, sed,
copy, concatenation, PostgreSQL, or any target-provided code.

The TimescaleDB checkout remains fail-closed on its symlinked directory. No
generation plan bypassed that boundary.
