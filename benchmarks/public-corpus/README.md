# Public corpus pilot

This pilot measures PgExtAssure against pinned revisions of public PostgreSQL
extension repositories. It is a scanner-quality benchmark, not a ranking of
the projects and not a claim that any finding is exploitable.

The initial manifest intentionally covers different package shapes and
capability profiles: C extensions, Rust extensions, SQL-heavy packages,
background workers, network-capable extensions, and large multi-version
upgrade graphs.

## Safety boundary

The corpus runner:

- accepts existing local Git checkouts;
- verifies every checkout against the exact commit in `manifest.tsv`;
- reads supported source files through PgExtAssure;
- does not build, install, import, load, or execute corpus code;
- writes a normalized aggregate without source excerpts;
- writes full reports only when `--raw-report-dir` is explicitly supplied.

Keep raw reports outside the public repository until findings have been
manually reviewed, deduplicated by root cause, and handled through an
appropriate disclosure process. The repository ignores `benchmark-results/`
for this reason.

## Checkout layout

Create one checkout per `repository` value:

```text
/path/to/corpus/
  hypopg/
  pg_cron/
  pg_net/
  ...
```

Each checkout must be detached at the exact 40-character commit recorded in
`manifest.tsv`. Some monorepositories use a narrower `scan_path` pointing at
the extension package inside the checkout. Fetching is deliberately separate
from scanning so the scan itself has no network behavior.

## Run

From a PgExtAssure development checkout:

```bash
python -m pip install --no-deps -e .
python tools/run_public_corpus.py /path/to/corpus
```

The default normalized output is:

```text
benchmark-results/public-corpus/summary.json
benchmark-results/public-corpus/summary.tsv
```

To retain evidence-bearing reports for private adjudication:

```bash
python tools/run_public_corpus.py /path/to/corpus \
  --raw-report-dir /private/path/to/raw-reports
```

The normalized output includes pinned revisions, source-manifest digests,
severity totals, capability categories, and rule counts. It deliberately
omits evidence excerpts and line-level findings. A scan that completes for
every checkout exits `0`; a completed corpus run with one or more fail-closed
scan errors exits `1`; manifest, checkout, or output errors exit `2`.

The first reproducible pilot is documented in
[RESULTS-2026-07-28.md](RESULTS-2026-07-28.md).
The conservative root-cause grouping follow-up is documented in
[GROUPING-2026-07-28.md](GROUPING-2026-07-28.md).

## Publication gate

Do not publish a corpus result merely because the runner completed. Before a
versioned benchmark is committed:

1. reproduce it from clean pinned checkouts;
2. review every critical and high record;
3. group repeated matches by root cause;
4. label each reviewed root cause as accepted capability, actionable defect,
   likely false positive, or unresolved;
5. privately notify upstream maintainers before publishing a potentially
   undisclosed vulnerability;
6. state the exact PgExtAssure and ruleset versions.
