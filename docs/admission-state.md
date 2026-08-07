# Baselines and suppressions

PgExtAssure can separate existing review debt from newly introduced root causes
without deleting findings from the report. Admission state is explicit,
versioned, digest-bound, and limited to exact `root_cause_id` values.

There are no wildcard, rule-wide, path-wide, severity-wide, or capability-wide
suppressions.

## Create a baseline candidate

```bash
pgextassure baseline /path/to/extension \
  --created-on 2026-07-29 \
  --output pgextassure-baseline.json
```

The command scans the same inputs as `pgextassure scan` and emits one entry for
each current root cause. It can also receive `--generation-plan`.

Generation is mechanical, not approval. Review the source report and the
baseline diff before committing or approving the file. The baseline contains
root-cause IDs, rules, severities, tool/ruleset versions, and source digests,
but not finding evidence.

Apply the reviewed baseline:

```bash
pgextassure scan /path/to/extension \
  --baseline pgextassure-baseline.json \
  --format grouped-json \
  --fail-on high
```

Existing matching root causes receive the `baselined` status and do not trip
the severity gate. New root causes remain `active` and block normally. Findings
and their evidence remain present in JSON, SARIF, text, and grouped reports.
Entries no longer present in the scan are reported as `stale`.

## Temporary suppressions

Suppressions are authored as a separate reviewed JSON file:

```json
{
  "schema_version": "1.0",
  "ruleset_version": "2026-08-07.1",
  "suppressions": [
    {
      "root_cause_id": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "rule_id": "sql.copy-program",
      "severity": "critical",
      "owner": "database-platform",
      "reason": "Required temporarily while SEC-123 is remediated.",
      "expires_on": "2026-08-31",
      "ticket": "SEC-123"
    }
  ]
}
```

Every suppression requires an owner, reason, and ISO expiry date. `ticket` is
optional. Do not put credentials, private evidence, or other secrets in these
fields because they are copied into machine-readable reports.

```bash
pgextassure scan /path/to/extension \
  --suppressions pgextassure-suppressions.json \
  --evaluated-on 2026-07-29 \
  --format sarif \
  --fail-on high
```

`expires_on` is inclusive. A suppression is active through that date and
becomes `expired` on the following day. Expired root causes are retained and
block the gate again. When `--evaluated-on` is omitted, PgExtAssure records and
uses the current UTC date. Supplying the date explicitly makes CI replay
deterministic.

Suppression-only and baseline-only workflows are supported. The same root cause
may not appear in both files during one scan; overlap fails closed rather than
silently choosing precedence.

## Ruleset binding

Baseline and suppression files bind the scanner `ruleset_version`. A mismatch
fails the scan. This forces a deliberate review when rule semantics change
instead of carrying old decisions into a new ruleset invisibly.

The exact root-cause ID, rule ID, and severity must agree with the current
finding group. Unknown entries do not suppress anything and are reported as
stale or unused.

## Report and gate behavior

Admission state does not change the report schema version; its metadata is an
optional top-level object.

With a baseline or suppressions:

- regular JSON uses schema `1.4` and adds an `admission` object;
- grouped JSON uses schema `1.3`, retains every root cause, and annotates each
  disposition;
- SARIF retains every result, records root-cause/status properties, marks
  baselined results as unchanged, and uses standard external suppressions for
  active temporary acceptances;
- text output shows admission totals and a status beside every finding;
- only `active` and `expired` root causes participate in `--fail-on`.

The report records exact baseline/suppression file digests, match/stale counts,
the evaluation date, and every applied decision.

## Fail-closed boundary

Admission files must be bounded regular UTF-8 JSON files. PgExtAssure rejects
symlinks, duplicate keys, unknown fields, malformed IDs, duplicate entries,
control characters, oversized fields/files, invalid dates, metadata
mismatches, overlapping dispositions, and stale ruleset versions.

Admission state records a scoped human decision. It does not prove
exploitability, remediation, runtime safety, or organizational authorization.

Normative contracts are published for
[baselines](../schemas/baseline-1.0.schema.json) and
[suppressions](../schemas/suppressions-1.0.schema.json). An
[organization policy](organization-policy.md) can make the gate centrally
reviewed and constrain whether these mechanisms are allowed.
