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
- Evidence Bundle index `1.0`;
- Corporate Evidence Signature statement `1.0`;
- Enterprise Trust Policy `1.0`;
- Admission Receipt `1.0`;
- Enterprise Pilot Package manifest `1.0`;
- Enterprise Admission Event `1.0`;
- Integration Export Manifest `1.0`;
- Admission Gateway Error `1.0`.

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

Corporate Evidence Signature statement `1.0` is described by
[`evidence-signature-1.0.schema.json`](../schemas/evidence-signature-1.0.schema.json).
The offline verifier additionally requires canonical JSON, a matching
RSA-PSS-SHA256 signature with an RSA key of at least 3072 bits, exact subject
bytes, and exact verified Evidence Bundle metadata.

Enterprise Trust Policy `1.0` is described by
[`enterprise-trust-policy-1.0.schema.json`](../schemas/enterprise-trust-policy-1.0.schema.json).
Admission Receipt `1.0` is described by
[`admission-receipt-1.0.schema.json`](../schemas/admission-receipt-1.0.schema.json).
The receipt verifier additionally recomputes the complete document from the
signed Evidence Bundle, exact trust policy, and externally expected request
context.

Enterprise Pilot Package manifest `1.0` is described by
[`pilot-package-1.0.schema.json`](../schemas/pilot-package-1.0.schema.json).
The non-extracting package verifier additionally enforces a closed flat
payload, canonical manifest bytes, exact entry sizes and digests, release
distribution checksums, resource limits, and private-key marker rejection.

Enterprise Admission Event `1.0` is described by
[`admission-event-1.0.schema.json`](../schemas/admission-event-1.0.schema.json).
It is emitted only after package, signature, receipt, external trust anchors,
and request context have been recomputed by the one-shot enterprise gate.

Integration Export Manifest `1.0` is described by
[`integration-export-1.0.schema.json`](../schemas/integration-export-1.0.schema.json).
It binds a vendor-specific HTTP payload to its exact Admission Event, profile,
request path, media type, byte length, and SHA-256 digest.

Admission Gateway Error `1.0` is described by
[`gateway-error-1.0.schema.json`](../schemas/gateway-error-1.0.schema.json).
Active and inactive admission responses use Admission Event `1.0`; only HTTP
request, replay, capacity, integrity, and internal failures use this contract.

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
