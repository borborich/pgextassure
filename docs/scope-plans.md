# Digest-bound scope plans

PgExtAssure normally scans one file or one complete directory tree and fails
closed on supported symlinks, symlinked directories, and supported files above
the per-file limit. Scope Plan `1.0` lets a reviewer narrow a directory scan
without turning those boundaries into untracked ignore patterns.

```bash
pgextassure scan /path/to/checkout \
  --scope-plan /path/to/scope-plan.json \
  --format json
```

The published contract is
[`schemas/scope-plan-1.0.schema.json`](../schemas/scope-plan-1.0.schema.json).

```json
{
  "schema_version": "1.0",
  "roots": ["extension", "shared/include"],
  "exclusions": [
    {
      "path": "extension/test/large.sql",
      "kind": "regular",
      "sha256": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    },
    {
      "path": "extension/sql/legacy.sql",
      "kind": "symlink",
      "sha256": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    }
  ]
}
```

## Contract

- `roots` are canonical POSIX-relative directories inside the requested scan
  directory. Roots must be unique and must not overlap. Use `"."` for the
  complete tree.
- A `regular` exclusion hashes the exact file bytes.
- A `symlink` exclusion hashes the exact link-target bytes returned by the
  filesystem. PgExtAssure never follows the link.
- Exclusion paths are exact. Globs, recursive patterns, directories, and
  unpinned ignores are not supported.
- Every declared exclusion must be encountered exactly once under a declared
  root. A missing, moved, changed, mistyped, or unused entry fails the scan.
- An undeclared supported symlink or symlinked directory still fails closed.
- Excluded regular files are read only to verify their digest and are bounded
  to 64 MiB each and 256 MiB in total.

The report records the exact plan digest, roots, and exclusions under `scope`.
Coverage records each accepted exclusion with reason `scope_excluded`.
Evidence Bundle creation includes the exact plan bytes as
`inputs/scope-plan.json`, so an offline verifier can bind the decision to the
same reviewed input.

A scope plan requires a directory scan. A generation plan may be combined with
a scope plan only when the declared scope root is `"."`; this prevents virtual
build artifacts from silently escaping a narrowed multi-root analysis.
