# GitHub annotations

PgExtAssure can emit GitHub workflow commands that place bounded annotations
on the first location of each root cause. The normal JSON, grouped JSON, SARIF,
or text report remains the complete evidence record.

```bash
pgextassure scan /path/to/extension \
  --format json \
  --output pgextassure.json \
  --github-annotations active \
  --max-annotations 25
```

`--output` is mandatory when annotations are enabled. GitHub workflow commands
are written to stdout, so keeping the report in a separate file prevents mixed
machine-readable output.

Modes:

- `none` emits no workflow commands and is the default;
- `active` emits active and expired root causes;
- `all` also emits baselined and suppressed root causes as notices.

Critical and high active root causes are errors, medium ones are warnings, and
low or accepted root causes are notices. A policy coverage violation is an
error without a file location. If the limit is reached, the final line is a
truncation notice and the complete report remains authoritative.

Annotations deliberately omit the scanner's matched source evidence. Paths,
titles, and messages are sanitized and escaped before workflow-command
rendering. This reduces log disclosure and command-injection risk, but workflow
logs and annotations should still be governed as security artifacts.

The emitted syntax follows GitHub's
[workflow-command contract](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands).

For the composite Action:

```yaml
- uses: borborich/pgextassure@v0.1.0-alpha.8
  with:
    path: .
    format: sarif
    output: pgextassure.sarif
    annotations: active
    max-annotations: "25"
    fail-on: high
```

Replace the version tag with the immutable release commit SHA in
higher-assurance workflows.
