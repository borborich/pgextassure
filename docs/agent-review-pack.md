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

Create a deterministic unresolved Decision Ledger:

```bash
pgextassure review template pgextassure-review.json \
  --output pgextassure-decisions.json
```

An agent may replace `unresolved` entries using the closed disposition
vocabulary. Every resolved entry requires a non-placeholder reviewer,
rationale, and at least one citation. Verify the result offline:

```bash
pgextassure review verify \
  pgextassure-review.json \
  pgextassure-decisions.json
```

Verification rejects stale pack digests, missing, extra, or duplicate tasks,
unknown fields or dispositions, unbounded text, and resolved decisions without
review evidence. A valid ledger still states `can_grant_admission: false`.
Human approval remains separate from agent-authored analysis.

The published Draft 2020-12 schema is
[`schemas/agent-review-pack-1.0.schema.json`](../schemas/agent-review-pack-1.0.schema.json).
The Decision Ledger schema is
[`schemas/agent-review-decisions-1.0.schema.json`](../schemas/agent-review-decisions-1.0.schema.json).
