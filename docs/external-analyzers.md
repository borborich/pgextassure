# External analyzer evidence

PgExtAssure External Analysis `1.0` turns saved output from a supported
specialist analyzer into deterministic, digest-bound review evidence. The
first profile supports the exact single-file text format emitted by pgspot
`0.9.2`.

The adapter does not install or execute pgspot. Run the analyzer in a separate,
reviewed environment, retain its stdout and process exit code, and then import
those bytes:

```bash
set +e
pgspot sql/extension.sql > pgspot.stdout
pgspot_exit=$?
set -e

pgextassure adapter pgspot sql/extension.sql \
  --stdout pgspot.stdout \
  --subject-path sql/extension.sql \
  --analyzer-version 0.9.2 \
  --exit-code "$pgspot_exit" \
  --output pgspot.external-analysis.json
```

The command accepts only exit code `0` for a clean summary and exit code `1`
when diagnostics exist. The analyzer version is recorded as `declared`: the
adapter does not claim to prove which binary produced the saved text.

Independently rebuild and compare the document against the exact SQL and stdout
bytes:

```bash
pgextassure adapter verify pgspot.external-analysis.json \
  --source sql/extension.sql \
  --stdout pgspot.stdout
```

Verification rejects changed inputs, non-canonical or duplicate-key JSON,
symlinks, unsupported versions and rules, malformed lines, unstructured
`Unknown` diagnostics, inconsistent counters, and inconsistent process exit
codes. The document binds:

- the source's relative review path, byte length, and SHA-256;
- the raw stdout byte length and SHA-256;
- the declared analyzer and fixed adapter profiles;
- every diagnostic's native rule, normalized rule, level, title, message,
  approximate source line, and source path;
- independently checked error, warning, unknown, and total counters.

## Boundary and limitations

External Analysis `1.0` is observational evidence. It does not alter a
PgExtAssure admission decision, enter Evidence Bundle `1.0`, certify the source
as safe, or prove analyzer-binary provenance. Pgspot's own line reporting is
approximate, and PgExtAssure preserves those reported lines without claiming
greater precision.

The profile intentionally fails closed on output not understood exactly. It
supports one source file per invocation, with no `--summary-only`, `--append`,
or multi-file headings. An unknown procedural-language message is not silently
normalized; review or configure pgspot so it emits a fully structured supported
result.

The versioned JSON Schema is
[`external-analysis-1.0.schema.json`](../schemas/external-analysis-1.0.schema.json).
Schema validation checks structure; the command-line verifier additionally
recomputes all correlations and semantic invariants from the original bytes.
