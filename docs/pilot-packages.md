# Enterprise Pilot Package 1.0

Enterprise Pilot Package 1.0 is a deterministic, flat ZIP handoff for an
offline corporate evaluation. It binds the signed Evidence Bundle, Trust
Policy, Admission Receipt, independent verification records, exact
PgExtAssure distributions, release checksums, and receiving-team guidance
under one canonical manifest.

It is a transport and audit container. It is not an installation
authorization, security certificate, or replacement for independently
delivered trust anchors.

## Required staging layout

The staging directory must contain exactly:

```text
README.md
acceptance-criteria.md
enterprise-trust-policy.json
evidence-verify.json
pgextassure-admission-receipt.json
pgextassure-evidence.zip
pgextassure-public-key.pem
pgextassure-signature.bin
pgextassure-signature.json
receipt-verify.json
release-provenance.json
release-SHA256SUMS
security-questionnaire.md
signature-verify.json
verification.md
pgextassure-VERSION-py3-none-any.whl
pgextassure-VERSION.tar.gz
```

`release-SHA256SUMS` must authenticate the exact included wheel and source
distribution. `release-provenance.json` retains the independently verified
GitHub/Sigstore result for those distributions. Keep the private key outside
the staging directory.

Create the package:

```bash
pgextassure pilot package STAGING_DIRECTORY \
  --output pgextassure-enterprise-pilot.zip \
  --format json
```

The command rejects:

- missing or unexpected files;
- nested paths, unsafe names, directories, and symlinks;
- multiple or incorrectly named distributions;
- distribution bytes not authenticated by `release-SHA256SUMS`;
- common PEM, OpenSSH, and PuTTY private-key markers;
- files, entry counts, or aggregate content outside bounded limits;
- output inside the staging directory.

The archive is deterministic for an identical staging directory. ZIP entry
names, timestamps, permissions, compression settings, and ordering are
canonical.

## Independent non-extracting verification

```bash
pgextassure pilot verify-package \
  pgextassure-enterprise-pilot.zip \
  --format json
```

Verification reads the package without extracting it. It rejects duplicate or
unsafe paths, unsupported compression, size violations, non-canonical or
duplicate-key manifests, checksum mismatches, unexpected payloads, and
private-key markers.

The embedded `pilot-package.json` uses the published
[`pilot-package-1.0.schema.json`](../schemas/pilot-package-1.0.schema.json)
contract. It records the exact path, byte size, and SHA-256 digest of every
payload file.

After the outer package verifies, independently verify:

1. the included distribution against the separately trusted release record
   and GitHub/Sigstore provenance;
2. the Evidence Bundle;
3. the corporate signature against an out-of-band public-key fingerprint;
4. the Admission Receipt against an out-of-band Trust Policy digest and
   expected request context.

The private key must never be delivered. The expected public-key fingerprint,
Trust Policy digest, request ID, target, and evaluation date remain external
authorization inputs. Do not treat values found only inside the ZIP as trust
anchors.
