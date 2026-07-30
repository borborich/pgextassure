# Self-service pilot acceptance

`pgextassure pilot accept` gives a receiving organization one closed command
for validating an Enterprise Pilot Package and its deployed Admission Gateway.
It does not require Kubernetes access, a vendor service, or a manual demo.

The receiving organization supplies the package, trust anchors obtained through
an independent channel, and its own TLS client material. The command writes a
canonical Pilot Acceptance Report 1.0 that can be retained as procurement,
security-review, or change-management evidence.

## Prerequisites

The target gateway must:

- expose one HTTPS origin with no path prefix;
- permit TLS 1.3 only;
- require an organization-issued client certificate;
- expose the Admission Gateway `/readyz` and `/v1/admissions` contracts;
- use an empty ledger context for the chosen request and idempotency key.

Keep these inputs outside the Pilot Package:

- complete package SHA-256;
- corporate public-key SHA-256;
- reviewed Enterprise Trust Policy SHA-256;
- expected request ID, target, and evaluation date;
- gateway CA certificate;
- client certificate and mode-`0600` client private key.

The private key path, key bytes, certificate paths, and raw idempotency key are
never written to the report. The report does retain SHA-256 digests of the
exact CA and client-certificate bytes plus the observed server leaf
certificate. Those non-secret identities bind the result to the accepted mTLS
boundary.

## Run

Use a new idempotency key for every acceptance run:

```bash
chmod 600 pilot-client-key.pem

pgextassure pilot accept pgextassure-enterprise-pilot.zip \
  --gateway-url https://pgextassure-gateway.example.internal \
  --ca-certificate gateway-ca.pem \
  --client-certificate pilot-client.pem \
  --client-key pilot-client-key.pem \
  --expected-package-sha256 sha256:PACKAGE_DIGEST \
  --expected-key-sha256 sha256:PUBLIC_KEY_FINGERPRINT \
  --expected-trust-policy-sha256 sha256:TRUST_POLICY_DIGEST \
  --expected-request-id CHG-2026-0042 \
  --expected-target postgresql-prod/extension-slot-01 \
  --expected-evaluated-on 2026-07-29 \
  --verified-on 2026-07-29 \
  --idempotency-key pilot-CHG-2026-0042-acceptance-01 \
  --output pgextassure-pilot-acceptance.json \
  --format json
```

Do not copy anchors from the package being tested. Obtain them from an
organization-owned configuration repository, protected CI environment, or
another authenticated channel.

## Acceptance contract

Checks run in this fixed order and stop on the first failure:

1. independently enforce the package against every external anchor;
2. require a canonical ready response over TLS 1.3 with the client certificate;
3. require a connection without the client certificate to yield no HTTP
   response;
4. require a TLS 1.2 connection to fail;
5. require the first admission to return the exact locally recomputed active
   Admission Event with `X-PgExtAssure-Replayed: false`;
6. repeat the request and require byte-identical output with
   `X-PgExtAssure-Replayed: true`.

Before verification, the runner reads each bounded regular input once and
copies the exact bytes into a private temporary directory. Offline enforcement
and the network request therefore use the same package bytes. The temporary
material is deleted after the run.

## Result and exit codes

Exit `0` means all six checks passed. Exit `1` means the report was written but
at least one acceptance check failed. Exit `2` means the command configuration
or output path was invalid.

Every report contains six ordered checks. Later checks are `not-run` after the
first failure. Failure causes use closed codes rather than exception messages,
so local paths, certificate details, and internal error text do not leak into
the retained artifact.

The published schema is
[`pilot-acceptance-report-1.0.schema.json`](../schemas/pilot-acceptance-report-1.0.schema.json).

An already used idempotency key intentionally fails `first-admission`: the
gateway correctly marks that response as a replay, so it cannot prove that the
current run performed the first admission. Choose a fresh key and an unused
request/target context.
