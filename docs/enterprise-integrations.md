# Enterprise admission integrations

PgExtAssure exposes one enforcement boundary for CI systems, deployment
controllers, ticketing systems, and SIEM ingestion. It verifies an Enterprise
Pilot Package from first principles and emits a canonical Admission Event 1.0.
No network service or embedded verification report is trusted.

## One-shot enforcement

Keep these values outside the package and obtain them through an independent
trusted channel:

- SHA-256 of the complete Pilot Package;
- SHA-256 fingerprint of the corporate public key;
- SHA-256 of the reviewed Enterprise Trust Policy;
- request ID, target, and evaluation date.

Run:

```bash
pgextassure pilot enforce pgextassure-enterprise-pilot.zip \
  --expected-package-sha256 sha256:PACKAGE_DIGEST \
  --expected-key-sha256 sha256:PUBLIC_KEY_FINGERPRINT \
  --expected-trust-policy-sha256 sha256:TRUST_POLICY_DIGEST \
  --expected-request-id CHG-2026-0042 \
  --expected-target postgresql-prod/extension-slot-01 \
  --expected-evaluated-on 2026-07-29 \
  --verified-on 2026-07-29 \
  --event-output pgextassure-admission-event.json \
  --format json
```

The command:

1. verifies the complete package and its externally expected digest without
   extracting it;
2. materializes only the already verified required payloads in a private
   temporary directory;
3. independently verifies the Evidence Bundle signature against the external
   key fingerprint;
4. recomputes the Admission Receipt against the external policy digest and
   request context;
5. emits Admission Event 1.0.

Exit `0` means the recomputed admission is active. Exit `1` means the package
is authentic but its decision is deny or its admit receipt is not active.
Exit `2` is invalid CLI input. Exit `3` is an integrity, signature, policy, or
request-context failure.

## Admission Event 1.0

The event is closed-schema canonical JSON. It records:

- deterministic event ID and observation date;
- `allow` or `deny` outcome and active state;
- externally bound request context;
- complete package and manifest digests;
- receipt decision, reasons, and validity end;
- trust-policy identity and digest;
- Evidence Bundle subject, gate, component, and tool identity;
- signer identity, key fingerprint, and signature date.

The schema is
[`admission-event-1.0.schema.json`](../schemas/admission-event-1.0.schema.json).
The same JSON can be retained as a CI artifact, attached to Jira or ServiceNow,
or ingested by a SIEM. Those systems should map fields from this event instead
of parsing human-readable output. PgExtAssure deliberately does not store API
credentials or send the event over a network.

## GitHub Action

The dedicated sub-action is addressed as
`borborich/pgextassure/admission@IMMUTABLE_COMMIT`. It fails the job unless the
event outcome is `allow`, while retaining the canonical event at the requested
path. See
[`examples/enterprise/admission-gate.yml`](../examples/enterprise/admission-gate.yml).

Store non-secret trust anchors in protected environment variables or an
organization-owned configuration repository. Treat the expected request
context as deployment input, not as values copied from the package.

## Credential-free vendor exports

`integration export` accepts only canonical Admission Event 1.0. It rejects
duplicate JSON keys, unknown fields, non-canonical bytes, invalid dates and
digests, semantic disagreement between `active` and `outcome`, and an event ID
that does not match the complete event content.

The command performs no network requests and reads no API credentials. It
creates the exact body for an organization-owned delivery step.

### Jira Cloud REST API v3

```bash
pgextassure integration export pgextassure-admission-event.json \
  --profile jira-cloud-v3 \
  --project SEC \
  --issue-type "Security Review" \
  --output jira-create-issue.json \
  --manifest-output jira-export-manifest.json
```

Send `jira-create-issue.json` as `application/json` to
`POST /rest/api/3/issue`. The description uses Atlassian Document Format. The
complete source event is retained as the
`pgextassure.admission-event` issue property. Jira project and issue-type field
configuration remains organization-owned and should be checked with Jira
create-field metadata before delivery.

### ServiceNow Change Request Table API

```bash
pgextassure integration export pgextassure-admission-event.json \
  --profile servicenow-change \
  --table change_request \
  --output servicenow-change.json \
  --manifest-output servicenow-export-manifest.json
```

Send the body to `POST /api/now/table/change_request`. It uses common task
fields: `short_description`, `description`, `correlation_id`, and
`work_notes`. The canonical event is retained in `work_notes`. Confirm table
ACLs, mandatory fields, and any organization-specific field mapping in the
target instance.

### Splunk HTTP Event Collector

```bash
pgextassure integration export pgextassure-admission-event.json \
  --profile splunk-hec \
  --index security_events \
  --output splunk-hec.json \
  --manifest-output splunk-export-manifest.json
```

Send the JSON object to `POST /services/collector/event`. It uses source
`pgextassure`, sourcetype `pgextassure:admission`, flat indexed fields for
correlation, and the complete Admission Event as the HEC `event`.

### Elastic Bulk API

```bash
pgextassure integration export pgextassure-admission-event.json \
  --profile elastic-bulk \
  --index pgextassure-admission \
  --output elastic-bulk.ndjson \
  --manifest-output elastic-export-manifest.json
```

Send the two-line `application/x-ndjson` payload to `POST /_bulk`. The event ID
becomes the idempotent Elastic document ID. The document contains
`@timestamp` plus the complete event under `pgextassure`.

## Integration Export Manifest 1.0

Every profile can write a canonical manifest with:

- profile and exact HTTP method/path/media type;
- payload byte length and SHA-256;
- source Admission Event ID and canonical event SHA-256.

The closed schema is
[`integration-export-1.0.schema.json`](../schemas/integration-export-1.0.schema.json).
The sender can retain the manifest beside the ticket, log, or delivery job and
verify that the body sent to the vendor API was the body produced from the
admitted event.

The same export is available as a composite sub-action:

```yaml
- uses: borborich/pgextassure/integration@IMMUTABLE_COMMIT
  with:
    event: pgextassure-admission-event.json
    profile: splunk-hec
    index: security_events
    output: pgextassure-splunk-hec.json
    manifest-output: pgextassure-integration-export.json
```

The Action still performs no delivery and receives no vendor credential. An
organization-owned step can compare the manifest digest, attach its own
authentication, and send the retained payload.

Vendor formats follow the official
[Jira Cloud REST API v3](https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/),
[Splunk HEC event format](https://docs.splunk.com/Documentation/Splunk/9.4.2/Data/HECExamples),
and
[Elastic Bulk API](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html)
contracts. ServiceNow instances can customize tables and fields, so the
receiving instance remains the authority for its final field map.
