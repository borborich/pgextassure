# PgExtAssure corporate pilot kit

This directory is the handoff package for a bounded PostgreSQL-extension
admission pilot. It is designed to be copied into an internal repository and
evaluated without giving PgExtAssure source code, credentials, network access,
or installation authority.

Use the parent
[`policy.json`](../policy.json) and [`pgextassure.yml`](../pgextassure.yml) for
the GitHub workflow. For a network-independent evaluation, use Evidence Bundle
1.0 and Corporate Evidence Signature Profile 1.0.

## Deliverables

The supplier sends exactly these artifacts:

| Artifact | Purpose |
| --- | --- |
| `pgextassure-evidence.zip` | Verified report, inventory, and control inputs |
| `pgextassure-signature.json` | Canonical signed statement |
| `pgextassure-signature.bin` | Detached RSA-PSS-SHA256 signature |
| `pgextassure-public-key.pem` | Public verification key |
| trusted key fingerprint | Delivered through an independent trust channel |
| `enterprise-trust-policy.json` | Organization-owned signer and evidence trust anchor |
| `pgextassure-admission-receipt.json` | Recomputable admit or deny decision |

Source files are not embedded in the evidence ZIP. Reports can contain short
matched excerpts and must still be handled as security-sensitive artifacts.

## Thirty-minute acceptance path

1. Install the pinned PgExtAssure wheel in a disposable Python environment.
2. Confirm the wheel digest against the release record.
3. Obtain the expected public-key SHA-256 through a separate trusted channel.
4. Run the command in [`verification.md`](verification.md) without network.
5. Compare the reported key fingerprint with the trusted fingerprint.
6. Confirm the output says `valid` and inspect whether `Gate` is `pass` or
   `blocked`.
7. Change one byte in a copied artifact and confirm verification exits `3`.
8. Evaluate the signature against the reviewed enterprise trust policy and
   bind the receipt to the pilot request ID and target.
9. Recompute the receipt using independently expected request context and
   trust-policy digest.
10. Record the result against
   [`acceptance-criteria.md`](acceptance-criteria.md).

The pilot demonstrates a tamper-evident, independently verifiable admission
record. It does not authorize installation and does not represent a security
certificate.
