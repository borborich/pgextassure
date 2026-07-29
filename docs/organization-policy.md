# Organization policy

PgExtAssure can make one reviewed JSON file authoritative for an
organization's admission gate. This avoids duplicating severity flags across
repositories and lets a platform team deny exact capabilities or rules even
when their built-in severity is below the normal threshold.

Start from a packaged, ruleset-pinned profile:

```bash
pgextassure policy-template adoption \
  --output pgextassure-policy.json
```

`adoption` blocks critical findings plus network/process-execution
capabilities, permits reviewed baselines and suppressions, and requires tickets
for suppressions. `strict` additionally blocks high findings and broader
privileged capabilities, forbids admission exceptions, and permits no skipped
supported-source files.

Templates are starting points, not universal security policy. Review every
field, commit the result, require ownership approval, and regenerate or update
the pinned `ruleset_version` when upgrading PgExtAssure. If a strict policy is
stored inside the scanned root, the policy JSON itself is an unsupported file
and violates `maximum_skipped_files: 0`; scan the extension subdirectory or
keep the policy outside that root.

```json
{
  "schema_version": "1.0",
  "ruleset_version": "2026-07-28.4",
  "gate": {
    "minimum_severity": "high",
    "blocked_capabilities": [
      "process.execute",
      "network.client-server"
    ],
    "blocked_rules": [],
    "maximum_skipped_files": 0
  },
  "admission": {
    "allow_baseline": true,
    "allow_suppressions": true,
    "require_suppression_ticket": true
  }
}
```

Run the policy-owned gate:

```bash
pgextassure scan /path/to/extension \
  --policy pgextassure-policy.json \
  --format grouped-json \
  --output pgextassure-grouped.json
```

`--policy` and a non-`none` `--fail-on` cannot be combined. Rejecting the
ambiguous configuration prevents a repository from silently overriding the
organization gate.

The gate evaluates root causes after admission state is applied. Active and
expired root causes block when severity reaches `minimum_severity`, capability
exactly matches `blocked_capabilities`, or rule ID exactly matches
`blocked_rules`.

The gate also blocks when the report's skipped-file count exceeds
`maximum_skipped_files`. Set it to `0` for a complete supported-source-only
boundary or `null` to disable this condition.

Use `"minimum_severity": "none"` for a capability/rule-only policy. Selectors
are exact; wildcards and regular expressions are not supported.

The admission section can prohibit baseline or suppression files and can
require every suppression entry, including an unused entry, to carry a ticket.
Policy cannot change rule severities, create a suppression, remove a finding,
or hide evidence.

The policy is closed-schema, bounded, UTF-8 JSON. Unknown and duplicate fields,
symlinks, duplicate selectors, malformed selectors, non-boolean admission
settings, and a stale `ruleset_version` fail closed. Reports retain the exact
policy-file SHA-256, effective controls, and blocked root-cause IDs.

The normative machine-readable contract is
[`schemas/policy-1.0.schema.json`](../schemas/policy-1.0.schema.json).
