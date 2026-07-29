# Report schemas and coverage

PgExtAssure publishes JSON Schema Draft 2020-12 contracts in
[`schemas/`](../schemas/). Consumers should select a schema by the document's
`schema_version`, not by the installed package version.

Current contracts:

- regular scan report `1.4`;
- grouped root-cause report `1.3`;
- Agent Review Pack `1.0`;
- Agent Review Decision Ledger `1.0`;
- generation plan `1.0`;
- scope plan `1.0`;
- baseline `1.0`;
- suppressions `1.0`;
- organization policy `1.0`;
- Evidence Bundle index `1.0`.

Agent Review Pack `1.0` is described by
[`agent-review-pack-1.0.schema.json`](../schemas/agent-review-pack-1.0.schema.json).
It binds an authority-free review task queue to the exact grouped-report and
source-manifest digests.
Agent Review Decision Ledger `1.0` is described by
[`agent-review-decisions-1.0.schema.json`](../schemas/agent-review-decisions-1.0.schema.json).
The offline verifier correlates its complete task set with the exact pack and
does not convert review dispositions into admission state.

SARIF remains SARIF `2.1.0` and links the standard SchemaStore schema.

Evidence Bundle 1.0 is a bounded ZIP container whose canonical `bundle.json`
index is described by
[`evidence-bundle-1.0.schema.json`](../schemas/evidence-bundle-1.0.schema.json).
The offline verifier additionally checks archive safety, payload hashes,
manifest/coverage recomputation, exact control-input digests, and SPDX/report
consistency.

## Coverage inventory

Every regular and grouped report includes `coverage`. It records the number of
analyzed files and every file-like directory entry skipped because its type is
unsupported. Entries are deterministically ordered and identify the relative
path, filesystem kind, reason, and byte size for regular files.

Unsupported content is never opened or hashed. The coverage digest binds the
analyzed-file count and skipped metadata inventory, not the bytes of skipped
files. The source manifest separately hashes every analyzed file. Together
they make the static boundary visible without parsing arbitrary archives,
binaries, documentation, test data, or build outputs.

Discovery remains bounded by the 100,000-entry tree limit, so the explicit
inventory cannot grow without limit. Supported symlinks, symlinked directories,
and supported non-regular sources continue to fail closed unless an exact
reviewed scope exclusion pins the entry. Scope-excluded entries remain visible
in coverage and their digests are bound through the exact scope-plan material.

Formatting changes to an input policy, baseline, suppression file, generation
plan, or scope plan change that input's recorded digest. This deliberately binds
an admission result to exact reviewed bytes.
