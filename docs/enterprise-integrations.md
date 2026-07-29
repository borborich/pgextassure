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
