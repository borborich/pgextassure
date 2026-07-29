# Agent Review Pack

Agent Review Pack `1.0` is a deterministic, machine-readable work queue for a
security reviewer or an AI coding agent. It binds every task to the exact
grouped report and source manifest while deliberately granting the agent no
authority to admit an extension.

Create a pack:

```bash
pgextassure scan /path/to/postgres-extension \
  --format review-json \
  --output pgextassure-review.json \
  --fail-on none
```

The pack contains:

- the analyzed-source manifest digest and grouped-report digest;
- the complete bounded coverage inventory;
- one task per conservative root cause, including every retained location;
- the closed disposition vocabulary `accepted-capability`,
  `actionable-defect`, `false-positive`, or `unresolved`;
- required output fields for rationale, citations, and reviewer identity;
- applied generation, admission, and policy metadata when present.

It contains no source-file payloads and requires no source upload. Root-cause
records can still contain sensitive paths and matched evidence, so treat the
pack as a security artifact and do not send it to an external model unless the
organization has approved that data flow.

## Trust boundary

The pack states `can_grant_admission: false`. Agent output is review assistance,
not a policy decision, suppression, baseline, certificate, or proof of
exploitability. An authorized person must verify cited evidence and apply a
separate organization policy before admission.

The current contract intentionally exports immutable tasks only. A future
decision-ledger contract will validate agent responses against the pack digest,
require an exact decision for each root cause, and keep human approval
separate from the agent-authored analysis.

The published Draft 2020-12 schema is
[`schemas/agent-review-pack-1.0.schema.json`](../schemas/agent-review-pack-1.0.schema.json).
