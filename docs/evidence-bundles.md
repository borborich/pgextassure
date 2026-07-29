# Evidence Bundle 1.0

PgExtAssure Evidence Bundle 1.0 is a deterministic, bounded ZIP that binds one
scan report to its analyzed-source manifest, coverage boundary, SPDX inventory,
and exact admission-control inputs. It is intended for independent review and
external cryptographic attestation.

Create evidence:

```bash
pgextassure evidence create /path/to/extension \
  --policy /path/to/enterprise-policy.json \
  --created-on 2026-07-29 \
  --component-name example-extension \
  --component-version 2.0 \
  --output pgextassure-evidence.zip
```

The command writes a valid bundle even when the policy blocks admission, then
returns exit code `1`. Input or contract errors do not produce an admissible
bundle.

Verify without extracting:

```bash
pgextassure evidence verify pgextassure-evidence.zip \
  --predicate-output evidence-predicate.json \
  --sbom-output sbom.spdx.json
```

The verifier:

- refuses symlinked, non-regular, oversized, encrypted, duplicate, unindexed,
  path-traversing, and unsupported-compression entries;
- reads every entry under per-entry and total expansion limits;
- verifies every indexed SHA-256 and size;
- recomputes the scan manifest and coverage digests;
- recomputes finding counts, severity totals, capabilities and gate outcome;
- checks the report, policy and other control-input digests;
- checks that the SPDX inventory exactly matches analyzed manifest files;
- never extracts archive entries to the filesystem.

The normative index contract is
[`schemas/evidence-bundle-1.0.schema.json`](../schemas/evidence-bundle-1.0.schema.json).

## Contents

Every bundle contains:

- `bundle.json`: canonical Bundle 1.0 index and attestation predicate;
- `report.json`: canonical regular PgExtAssure report;
- `sbom.spdx.json`: SPDX 2.3 analyzed-source inventory.

When used, the exact raw JSON bytes of a generation plan, scope plan, baseline,
suppressions file, and organization policy are stored under `inputs/`. Their
SHA-256 values must match the provenance retained by `report.json`.

The ZIP contains no source-file payloads. The report still contains matched
evidence excerpts and paths, so the complete bundle is a security artifact and
may be unsuitable for public upload.

## SBOM scope

The SPDX document is deliberately labeled
`analyzed-source-inventory`. It includes only supported files whose bytes were
read and hashed by PgExtAssure. It does not claim to resolve skipped files,
generated outputs, build tools, package-manager state, or transitive
dependencies. Those boundaries remain explicit in `report.json`.

## Signing and verification

The signature is external to the ZIP to avoid a circular digest.

For network-independent corporate signing and verification, use Corporate
Evidence Signature Profile 1.0:

```bash
pgextassure evidence sign pgextassure-evidence.zip \
  --private-key corporate-release-key.pem \
  --signer-id acme-security/postgresql-admission-key-01 \
  --statement-output pgextassure-signature.json \
  --signature-output pgextassure-signature.bin \
  --public-key-output pgextassure-public-key.pem

pgextassure evidence verify-signature pgextassure-evidence.zip \
  --statement pgextassure-signature.json \
  --signature pgextassure-signature.bin \
  --public-key pgextassure-public-key.pem \
  --expected-key-sha256 'sha256:TRUSTED_64_HEX_DIGEST'
```

The signer and verifier both validate the complete Evidence Bundle. The
detached statement also binds the verified gate, manifest, coverage, policy,
signer, and public-key fingerprint. See
[Corporate signatures](corporate-signatures.md).

In GitHub Actions, an alternative is to use `actions/attest` with:

- subject: `pgextassure-evidence.zip`;
- predicate type:
  `https://github.com/borborich/pgextassure/attestation/evidence/v1`;
- predicate: the verified `bundle.json` exported by the verifier.

Also create an SBOM attestation for the same subject using the exported SPDX
document. The caller workflow must grant `id-token: write` and
`attestations: write`.

Online verification:

```bash
gh attestation verify pgextassure-evidence.zip \
  --repo OWNER/EXTENSION-REPOSITORY \
  --predicate-type \
  https://github.com/borborich/pgextassure/attestation/evidence/v1
```

Cryptographic verification establishes signer identity and bundle integrity;
`pgextassure evidence verify` establishes the internal evidence contract.
Neither operation proves that the extension is safe.
