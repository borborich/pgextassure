# Enterprise Trust Policy and Admission Receipt 1.0

Enterprise Trust Policy 1.0 converts a cryptographically valid Evidence Bundle
signature into an explicit, organization-owned admission decision. It is a
local trust anchor, not content supplied by the extension author.

The policy constrains:

- accepted `pass` or `blocked` evidence gates;
- exact PgExtAssure, ruleset, Evidence Bundle, and organization-policy
  versions or digests;
- maximum Evidence Bundle and signature ages;
- receipt lifetime;
- exact signer IDs and DER public-key SHA-256 fingerprints;
- signer validity windows and effective revocation dates;
- the trust policy's own effective and expiry dates.

Start from
[`examples/enterprise/trust-policy.json`](../examples/enterprise/trust-policy.json).
The example fingerprint is deliberately all zeroes and trusts no real key.
Replace it with a fingerprint obtained through the organization's independent
PKI or key-distribution channel.

## Create an Admission Receipt

```bash
pgextassure trust evaluate pgextassure-evidence.zip \
  --statement pgextassure-signature.json \
  --signature pgextassure-signature.bin \
  --public-key pgextassure-public-key.pem \
  --trust-policy enterprise-trust-policy.json \
  --evaluated-on 2026-07-29 \
  --request-id CHG-2026-0042 \
  --target postgresql-prod-eu/extension-slot-01 \
  --output pgextassure-admission-receipt.json \
  --format json
```

The command always retains a canonical receipt after successful
cryptographic verification:

- exit `0`: decision is `admit`;
- exit `1`: decision is `deny`, with closed reason codes;
- exit `2`: policy, request, date, or output usage is invalid;
- exit `3`: evidence, signature, or cryptographic correlation failed.

A signed `blocked` Evidence Bundle is normally a valid input that produces a
`deny` receipt. It is not discarded as an invalid artifact.

The receipt binds the exact bundle, gate, component, manifest, coverage,
evidence policy, tool/ruleset, corporate signature, trust-policy digest,
evaluation date, request ID, and deployment target. An admitted receipt's
`valid_until` is clipped to the shortest applicable policy, evidence,
signature, signer, or configured receipt lifetime.

## Independently verify and enforce a receipt

```bash
pgextassure trust verify-receipt \
  pgextassure-admission-receipt.json \
  --bundle pgextassure-evidence.zip \
  --statement pgextassure-signature.json \
  --signature pgextassure-signature.bin \
  --public-key pgextassure-public-key.pem \
  --trust-policy enterprise-trust-policy.json \
  --expected-trust-policy-sha256 \
  'sha256:TRUSTED_64_HEX_DIGEST' \
  --expected-request-id CHG-2026-0042 \
  --expected-target postgresql-prod-eu/extension-slot-01 \
  --expected-evaluated-on 2026-07-29 \
  --verified-on 2026-07-29 \
  --format json
```

Verification completely recomputes the receipt from the original signed
evidence and exact trust policy. The externally supplied trust-policy digest,
request ID, target, and evaluation date are trust anchors and prevent a
modified receipt from redefining its own authorization context.

The verifier exits `0` only for a valid, admitted, currently active receipt. It
exits `1` for a correctly recomputed deny or an expired/not-yet-active receipt.
Malformed or mismatched receipts fail with exit `3`.

## Closed deny reasons

Admission Receipt 1.0 uses only these reason codes:

- `trust-policy-not-effective`, `trust-policy-expired`;
- `gate-not-allowed`;
- `tool-version-not-allowed`, `ruleset-version-not-allowed`,
  `evidence-schema-not-allowed`, `evidence-policy-not-allowed`;
- `evidence-from-future`, `evidence-too-old`;
- `signature-before-evidence`, `signature-from-future`,
  `signature-too-old`;
- `untrusted-signer`, `signer-not-yet-valid`, `signer-expired`,
  `signer-revoked`.

## Replay and authority boundary

PgExtAssure binds each receipt to a bounded request ID and target but does not
operate a shared transaction database. The deployment, ticket, or admission
system must enforce request-ID uniqueness and one-time use where replay
prevention is required. Offline verification cannot determine whether the same
otherwise-valid receipt was already consumed elsewhere.

An Admission Receipt is deterministic and independently recomputable; Profile
1.0 does not add a second signature over the receipt. Its integrity comes from
the signed Evidence Bundle, exact trust-policy bytes, and externally supplied
request context. A downstream system that needs a portable stand-alone
authorization token should sign or attest the receipt using its existing
deployment authority.

Trust policies and request context remain organizational authorization inputs.
PgExtAssure validates and applies them but cannot determine who was entitled to
approve or distribute those inputs.
