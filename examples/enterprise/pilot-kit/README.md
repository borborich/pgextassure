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
| `evidence-verify.json` | Retained Evidence Bundle verification result |
| `signature-verify.json` | Retained corporate-signature verification result |
| `receipt-verify.json` | Retained active/inactive receipt verification result |
| PgExtAssure wheel and sdist | Exact offline verifier distributions |
| `release-SHA256SUMS` | Release checksums for both distributions |
| `release-provenance.json` | Retained strict GitHub/Sigstore verification result |
| `pilot-package.json` | Generated manifest inside the final handoff ZIP |

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
11. Stage the required records and distributions, run `pgextassure pilot
    package`, then verify the resulting ZIP without extracting it.
12. Run `pgextassure pilot enforce` with separately delivered package, key,
    policy, and request-context anchors; retain Admission Event 1.0.

The pilot demonstrates a tamper-evident, independently verifiable admission
record. It does not authorize installation and does not represent a security
certificate.

The private key must stay outside the staging directory. Deliver the expected
public-key fingerprint and Trust Policy digest through an independent channel;
values present only inside the package are not trust anchors. The closed
package format is documented in
[`docs/pilot-packages.md`](../../../docs/pilot-packages.md).
CI and enterprise-system integration are documented in
[`docs/enterprise-integrations.md`](../../../docs/enterprise-integrations.md).
