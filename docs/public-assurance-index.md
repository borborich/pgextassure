# Public Extension Assurance Index

The PgExtAssure Extension Assurance Index is a reproducible inventory of static-analysis coverage for pinned public PostgreSQL extension revisions. It is not a security rating, certification, vulnerability report, endorsement, or allowlist decision.

The index is generated only from an existing normalized corpus `summary.json` and the exact TSV manifest used for that run. Generation performs no checkout, download, scan, or other network operation.

## Public fields

Each project row contains only:

- the public project name and repository URL;
- the pinned commit and its recorded date;
- whether analysis completed;
- for completed runs, the number of files analyzed and source-manifest digest;
- a capability profile, which describes observed functionality rather than vulnerabilities;
- whether reviewed generation or scope plans were used.

Finding counts, severities, rule identifiers, evidence, paths, source excerpts, and error messages are intentionally omitted. A non-completed run exposes only a stable failure class. The generator rejects evidence-bearing `findings` or `root_causes` collections instead of silently transforming them.

## Reproduce

First reproduce the normalized corpus run as described in [`benchmarks/public-corpus/README.md`](../benchmarks/public-corpus/README.md). Then run:

```bash
python tools/generate_assurance_index.py \
  --summary benchmark-results/public-corpus/summary.json \
  --manifest benchmarks/public-corpus/manifest.tsv \
  --output-dir benchmark-results/public-corpus/index
```

The command writes deterministic `index.json` and `index.md` files. The JSON follows [`public-assurance-index-1.0.schema.json`](../schemas/public-assurance-index-1.0.schema.json) and binds both input files by SHA-256.

For a versioned public snapshot, use only a normalized summary produced from the same manifest and pass the existing corpus publication gate before copying the generated files into a public location. Do not infer that a completed analysis means that an extension is safe.
