# Generation plans

PostgreSQL extension repositories often keep an install SQL file or final
control file out of the source tree and create it during `make`. PgExtAssure
does not execute Makefiles, shell commands, build hooks, or target code. An
optional generation plan lets a reviewer declare the expected artifacts
without weakening that boundary.

Use a plan only after reviewing the pinned build rule. A plan is an operator
assertion, not proof that the upstream build creates the declared artifact.
Treat a target-provided plan as untrusted until it has received the same review
as the source revision.

## CLI

```bash
pgextassure scan /path/to/extension \
  --generation-plan /path/to/reviewed-generation-plan.json \
  --format grouped-json \
  --output pgextassure-grouped.json
```

A scan with a generation plan requires a directory root. Regular JSON reports
use schema `1.3`; generation metadata is an optional top-level object. JSON,
grouped JSON, SARIF, and text reports all bind the generation-plan digest to
the result.

## Schema

The normative contract is
[`schemas/generation-plan-1.0.schema.json`](../schemas/generation-plan-1.0.schema.json).

```json
{
  "schema_version": "1.0",
  "artifacts": [
    {
      "path": "sql/example--2.0.sql",
      "inputs": [
        {
          "path": "Makefile",
          "sha256": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        },
        {
          "path": "sql/example.sql",
          "sha256": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        }
      ]
    },
    {
      "path": "example.control",
      "template": "example.control.in",
      "substitutions": {
        "EXTVERSION": "2.0"
      },
      "inputs": [
        {
          "path": "example.control.in",
          "sha256": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
        }
      ]
    }
  ]
}
```

Every input is relative to the scan root and pinned by SHA-256. A changed,
missing, symlinked, non-regular, escaping, or oversized input fails the scan.
Generated target paths may end only in lowercase `.sql` or `.control` and may
not conflict with a real scanned source.

## Artifact modes

An SQL artifact without `template` is `declared`. It contributes only its
reviewed virtual filename to install/update graph analysis. PgExtAssure does
not invent or scan content for it. The plan should pin the Makefile/build
metadata and relevant source inputs that justified the declaration.

An artifact with `template` is `rendered`. PgExtAssure:

1. verifies every input digest;
2. reads the named template as UTF-8 data;
3. applies only the listed literal substitutions in memory;
4. scans the rendered content at the generated target path;
5. avoids double-counting the original template;
6. records the rendered size and SHA-256 in the report.

Generated control artifacts require a template. Substitution tokens are limited
to uppercase identifiers such as `EXTVERSION` or `@EXTVERSION@`; values cannot
contain control characters and are size-bounded. The renderer does not support
shell syntax, variable expansion, expressions, includes, commands, or code.

## Fail-closed limits

Plans reject duplicate JSON keys, unknown fields, duplicate targets and inputs,
path traversal, symlinks, digest mismatches, unsafe substitutions, missing
tokens, and excessive plan, input, rendered-output, path, artifact, or
substitution counts and sizes.

The generation-plan digest covers the exact JSON bytes. Formatting changes
therefore create a new digest even when the declaration is semantically
equivalent. This makes an admission record unambiguous.

## Non-claims

A declared artifact can correct source-tree graph accounting, but it cannot
prove that a release package contains that artifact or that its generated
content matches the reviewed inputs. Higher-assurance workflows should compare
the eventual packaged artifact against a reproducible build in a separate,
isolated build system.
